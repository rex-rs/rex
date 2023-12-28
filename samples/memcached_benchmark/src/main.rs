// use async_memcached::*;
use clap::{Parser, Subcommand, ValueEnum};
use futures::future::join_all;
use memcache::MemcacheError;
use rand::distributions::{Alphanumeric, DistString, Distribution};
use serde_yaml;
use zstd;

use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::mem::size_of_val;
use std::result::Result;
use std::vec;
use std::{collections::HashMap, sync::Arc};

use rayon::prelude::*;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

extern crate r2d2_memcache;

const NUM_ENTRIES: usize = 10000;
const BUFFER_SIZE: usize = 1500;

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum Protocol {
    Udp,
    Tcp,
}

struct TaskData {
    buf: Vec<u8>,
    addr: Arc<String>,
    key: String,
    test_dict: Arc<HashMap<String, String>>,
    validate: bool,
    key_size: usize,
    value_size: usize,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(arg_required_else_help = true)]
    Bench {
        #[arg(short, long, default_value = "127.0.0.1")]
        server_address: String,

        #[arg(short, long, default_value = "11211")]
        port: String,

        /// key size to generate random memcached key
        #[arg(short, long, default_value = "16")]
        key_size: usize,

        /// value size to generate random memcached value
        #[arg(short, long, default_value = "32")]
        value_size: usize,

        /// verify the value after get command
        #[arg(short = 'd', long, default_value = "false")]
        validate: bool,

        /// number of test entries to generate
        #[arg(short, long, default_value = "100000")]
        nums: usize,

        // number of threads to run
        #[arg(short, long, default_value = "4")]
        threads: usize,

        /// udp or tcp protocol for memcached
        #[arg(short = 'l', long, default_value_t = Protocol::Udp , value_enum)]
        protocol: Protocol,
    },
    GenTestdict {
        #[arg(short, long, default_value = "16")]
        key_size: usize,
        #[arg(short, long, default_value = "32")]
        value_size: usize,
        #[arg(short, long, default_value = "100000")]
        nums: usize,
    },
}

fn generate_random_str(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}

fn generate_memcached_test_dict(
    key_size: usize,
    value_size: usize,
    nums: usize,
) -> HashMap<String, String> {
    // random generate dict for memcached test
    (0..nums)
        .into_par_iter()
        .map(|_| {
            (
                generate_random_str(key_size),
                generate_random_str(value_size),
            )
        })
        .collect()
}

async fn set_memcached_value(
    test_dict: Arc<HashMap<String, String>>,
    server_address: String,
    port: String,
) -> Result<(), MemcacheError> {
    // let mut client = Client::new(format!("{}:{}", args.server_address, args.port))
    //     .await
    //     .unwrap();
    let manager = r2d2_memcache::MemcacheConnectionManager::new(format!(
        "memcache://{}:{}",
        server_address, port
    ));
    let pool = r2d2_memcache::r2d2::Pool::builder()
        .max_size(100)
        .build(manager)
        .unwrap();

    test_dict.par_iter().for_each(|(key, value)| {
        let conn = pool.get().unwrap();
        conn.set(key, value.as_bytes(), 0).unwrap();
        let result: String = conn.get(key).unwrap().unwrap();
        assert!(result == *value);
    });

    println!("Done set memcaced value");

    Ok(())
}

fn exmaple_method(server: &memcache::Client) -> std::result::Result<(), MemcacheError> {
    // flush the database:
    server.flush()?;

    // set a string value:
    server.set("foo", "bar", 0)?;

    // retrieve from memcached:
    let value: Option<String> = server.get("foo")?;
    assert_eq!(value, Some(String::from("bar")));
    assert_eq!(value.unwrap(), "bar");

    // prepend, append:
    server.prepend("foo", "foo")?;
    server.append("foo", "baz")?;
    let value: String = server.get("foo")?.unwrap();
    assert_eq!(value, "foobarbaz");

    // delete value:
    server.delete("foo").unwrap();

    // using counter:
    server.set("counter", 40, 0).unwrap();
    server.increment("counter", 2).unwrap();
    let answer: i32 = server.get("counter")?.unwrap();
    assert_eq!(answer, 42);

    println!("memcached server works!");
    Ok(())
}

fn wrap_get_command(key: String, seq: u16) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0, 0, 0, 1, 0, 0];
    let mut command = format!("get {}\r\n", key).into_bytes();
    let mut seq_bytes = seq.to_be_bytes().to_vec();
    seq_bytes.append(&mut bytes);
    seq_bytes.append(&mut command);
    // println!("bytes: {:?}", seq_bytes);
    seq_bytes
}

async fn socket_task(socket: Arc<UdpSocket>, mut rx: mpsc::Receiver<TaskData>) {
    while let Some(TaskData {
        buf,
        addr,
        key,
        test_dict,
        validate,
        key_size,
        value_size,
    }) = rx.recv().await
    {
        // Send
        let _ = socket.send_to(&buf[..], addr.as_str()).await;

        // Then receive
        let mut buf = [0; BUFFER_SIZE];
        let my_duration = tokio::time::Duration::from_millis(500);

        if let Ok(Ok((amt, _))) = timeout(my_duration, socket.recv_from(&mut buf)).await {
            if validate {
                continue;
            }
            if let Some(value) = test_dict.get(&key) {
                let received = String::from_utf8_lossy(&buf[..amt])
                    .split("VALUE ")
                    .nth(1)
                    .unwrap_or_default()[6 + key_size + 1..6 + key_size + value_size + 1]
                    .to_string();

                if received != *value.to_string() {
                    println!(
                        "response not match key {} buf: {} , value: {}",
                        key, received, value
                    );
                }
            }
        }
    }
}

async fn get_command_benchmark(
    test_dict: Arc<HashMap<String, String>>,
    send_commands: Vec<(String, Vec<u8>)>,
    server_address: String,
    port: String,
    validate: bool,
    key_size: usize,
    value_size: usize,
) -> Result<(), Box<dyn Error>> {
    // assign client address
    let addr = Arc::new(format!("{}:{}", server_address, port));
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let socket = Arc::new(socket);
    // let addr_to: ToSocketAddrs = ToSocketAddrs::to_socket_addrs(addr).unwrap();

    let start = std::time::Instant::now();

    // Create the channel
    let (tx, rx) = mpsc::channel(100000);
    let socket_clone = Arc::clone(&socket);
    let socket_task = tokio::spawn(socket_task(socket_clone, rx));

    for (key, packet) in send_commands {
        let send_result = tx
            .send(TaskData {
                buf: packet,
                addr: addr.clone(),
                key,
                test_dict: test_dict.clone(),
                validate,
                key_size,
                value_size,
            })
            .await;
        if send_result.is_err() {
            // The receiver was dropped, break the loop
            break;
        }
    }

    // Wait for the socket task to finish
    socket_task.await?;

    // Close the channel
    drop(tx);

    let duration = start.elapsed();
    println!("Time elapsed in get_command_benchmark() is: {:?}", duration);

    Ok(())
}

fn get_server(
    addr: &String,
    port: &String,
    protocol: &Protocol,
) -> Result<memcache::Client, MemcacheError> {
    match protocol {
        Protocol::Udp => memcache::connect(format!("memcache+udp://{}:{}?timeout=10", addr, port)),
        Protocol::Tcp => memcache::connect(format!("memcache://{}:{}?timeout=10", addr, port)),
    }
}

fn write_hashmap_to_file(
    hashmap: &HashMap<String, String>,
    file_path: &str,
) -> std::io::Result<()> {
    // Serialize the hashmap to a JSON string
    let serialized = serde_yaml::to_string(hashmap).expect("Failed to serialize");

    // Create or open the file
    let file = File::create(file_path)?;

    // Create a zstd encoder with default compression level
    let mut encoder = zstd::stream::write::Encoder::new(file, 7)?;

    // Write the JSON string to the file
    encoder.write_all(serialized.as_bytes())?;
    encoder.finish()?;

    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 12)]
async fn main() -> std::result::Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    match args.command {
        Commands::Bench {
            server_address,
            port,
            key_size,
            value_size,
            validate,
            nums,
            threads,
            protocol,
        } => {
            let server = get_server(&server_address, &port, &protocol)?;
            exmaple_method(&server)?;
            server.flush()?;

            let test_dict = generate_memcached_test_dict(key_size, value_size, NUM_ENTRIES);
            println!("test dict len: {}", test_dict.len());
            if let Some((key, value)) = test_dict.iter().next() {
                println!("test dict key size: {}", size_of_val(key.as_str()));
                println!("test dict value size: {}", size_of_val(value.as_str()));
            } else {
                Err("test dict is empty")?;
            }

            println!("write test dict to file");
            write_hashmap_to_file(&test_dict, "test_dict.yml.zst")?;

            let test_dict = Arc::new(test_dict);

            set_memcached_value(test_dict.clone(), server_address.clone(), port.clone()).await?;

            let mut handles = vec![];

            for _ in 0..threads {
                let mut seq: u16 = 0;
                let mut send_commands = vec![];

                let keys: Vec<&String> = test_dict.keys().collect();
                let dict_len = keys.len();

                let mut rng = rand::thread_rng();
                let zipf = zipf::ZipfDistribution::new(dict_len - 1, 0.99).unwrap();

                // generate get commands for each thread
                for _ in 0..nums / threads {
                    let key = keys[zipf.sample(&mut rng)].clone();
                    let packet = wrap_get_command(key.clone(), seq);
                    seq = seq.wrapping_add(1);
                    send_commands.push((key, packet));
                }

                let test_dict = Arc::clone(&test_dict);
                let server_address = server_address.clone();
                let port = port.clone();
                let handle = tokio::spawn(async move {
                    match get_command_benchmark(
                        test_dict,
                        send_commands,
                        server_address,
                        port,
                        validate,
                        key_size,
                        value_size,
                    )
                    .await
                    {
                        Ok(_) => (),
                        Err(e) => eprintln!("Task failed with error: {:?}", e),
                    }
                });
                handles.push(handle);
            }
            // wait for all tasks to complete
            join_all(handles).await;

            // stats
            let stats = server.stats()?;
            println!("stats: {:?}", stats);
        }
        Commands::GenTestdict {
            key_size,
            value_size,
            nums,
        } => {}
    }

    Ok(())
}
