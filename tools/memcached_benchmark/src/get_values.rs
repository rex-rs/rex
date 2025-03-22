use std::{
    collections::HashMap,
    sync::{Arc, atomic::*},
};

use anyhow::Result;
use clap::ValueEnum;
use log::{info, trace};
use serde::{Deserialize, Serialize};
use tokio::{net::UdpSocket, sync::mpsc, time::timeout};
use tokio_util::task::TaskTracker;

use crate::{BUFFER_SIZE, TIMEOUT_COUNTER};

#[derive(
    ValueEnum, Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize,
)]
pub(crate) enum Protocol {
    Udp,
    Tcp,
}

struct TaskData {
    seq: u16,
    addr: Arc<String>,
    key: Arc<String>,
    test_dict: Arc<HashMap<Arc<String>, Arc<String>>>,
    validate: bool,
    key_size: usize,
    value_size: usize,
    counter: usize,
}

fn wrap_get_command(key: Arc<String>, seq: u16) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0, 0, 0, 1, 0, 0];
    let mut command = format!("get {}\r\n", key).into_bytes();
    let mut seq_bytes = seq.to_be_bytes().to_vec();
    seq_bytes.append(&mut bytes);
    seq_bytes.append(&mut command);
    trace!("bytes: {:?}", seq_bytes);
    seq_bytes
}

async fn socket_task(
    sockets_pool: Arc<Vec<UdpSocket>>,
    mut rx: mpsc::Receiver<TaskData>,
    tracker: TaskTracker,
) {
    let mut cnt = 0u64;
    while let Some(TaskData {
        seq,
        addr,
        key,
        test_dict,
        validate,
        key_size,
        value_size,
        counter,
    }) = rx.recv().await
    {
        let socket_pool_clone = Arc::clone(&sockets_pool);
        cnt += 1;
        tracker.spawn(async move {
            let send_timeout = tokio::time::Duration::from_millis(500);

            // Send
            let socket: &UdpSocket = &socket_pool_clone[counter & 0x1F];
            let packet = wrap_get_command(key.clone(), seq);
            // Add timeout action
            if (timeout(
                send_timeout,
                socket.send_to(&packet[..], addr.as_str()),
            )
            .await)
                .is_err()
            {
                TIMEOUT_COUNTER.fetch_add(1, Ordering::Relaxed);
                return;
            };

            // Then receive
            let mut buf = [0; BUFFER_SIZE];
            let my_duration = tokio::time::Duration::from_millis(500);

            if let Ok(Ok((amt, _))) =
                timeout(my_duration, socket.recv_from(&mut buf)).await
            {
                if !validate {
                    return;
                }
                if let Some(value) = test_dict.get(&*key) {
                    let received = String::from_utf8_lossy(&buf[..amt])
                        .split("VALUE ")
                        .nth(1)
                        .unwrap_or_default()
                        [6 + key_size + 1..6 + key_size + value_size + 1]
                        .to_string();

                    if received != *value.to_string() {
                        info!(
                            "response not match key {} buf: {} , value: {}",
                            key, received, value
                        );
                    }
                }
            } else {
                // Timeout occurred - increment the counter
                TIMEOUT_COUNTER.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    info!("processed tasks: {}", cnt);
}

pub(crate) async fn get_command_benchmark(
    test_dict: Arc<HashMap<Arc<String>, Arc<String>>>,
    send_commands: Vec<(Arc<String>, u16, Protocol, Arc<String>)>,
    server_address: String,
    port: String,
    validate: bool,
    key_size: usize,
    value_size: usize,
    pipeline: usize,
) -> Result<()> {
    // assign client address
    let addr = Arc::new(format!("{}:{}", server_address, port));

    let mut sockets_pool = vec![];
    for _ in 0..32 {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("couldn't bind to address");
        sockets_pool.push(socket);
    }
    let sockets_pool = Arc::new(sockets_pool);

    let mut client = async_memcached::Client::new(format!(
        "tcp://{}:{}",
        server_address, port
    ))
    .await
    .expect("TCP memcached connection failed");

    let tracker = TaskTracker::new();
    let cloned_tracker = tracker.clone();

    let start = std::time::Instant::now();

    // Create the channel
    let (tx, rx) = mpsc::channel(pipeline);

    tracker.spawn(socket_task(sockets_pool, rx, cloned_tracker));

    let mut counter = 0usize;
    let mut handles = vec![];

    for (key, seq, proto, value) in send_commands {
        // if tcp, use set request
        if proto == Protocol::Tcp {
            client
                .set(&*key, &*value, None, None)
                .await
                .expect("memcached set command failed");
            continue;
        }
        counter = counter.wrapping_add(1);
        let send_result = tx.send(TaskData {
            seq,
            addr: addr.clone(),
            key,
            test_dict: test_dict.clone(),
            validate,
            key_size,
            value_size,
            counter,
        });
        handles.push(send_result);
    }

    for handle in handles {
        handle.await?;
        // let metrics = Handle::current().metrics();
        // let n = metrics.active_tasks_count();
    }

    // Close the channel
    drop(tx);

    // Wait for the socket task to finish
    tracker.close();
    tracker.wait().await;

    let duration = start.elapsed();
    info!("Time elapsed in get_command_benchmark() is: {:?}", duration);

    Ok(())
}
