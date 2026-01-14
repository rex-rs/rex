use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use log::info;
use memcache_async::ascii::Protocol;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::compat::TokioAsyncReadCompatExt;

pub(super) async fn set_memcached_value(
    test_dict: Arc<HashMap<Arc<String>, Arc<String>>>,
    server_address: String,
    port: String,
) -> Result<()> {
    info!("Start set memcached value");
    let addr = format!("{}:{}", server_address, port);
    let mut sockets_pool = vec![];
    let concurrency_limit = 64;

    for _ in 0..concurrency_limit {
        let stream = TcpStream::connect(&addr)
            .await
            .expect("TCP memcached connection failed");
        let client = Protocol::new(stream.compat());
        sockets_pool.push(tokio::sync::Mutex::new(client));
    }
    let sockets_pool = Arc::new(sockets_pool);

    let mut set = JoinSet::new();
    let sem = Arc::new(Semaphore::new(concurrency_limit));

    for (count, (key, value)) in test_dict.iter().enumerate() {
        let sockets_pool_clone = sockets_pool.clone();
        let key_clone = key.clone();
        let value_clone = value.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let mut socket = sockets_pool_clone[count & 0x3F].lock().await;
            socket
                .set(&*key_clone, value_clone.as_bytes(), 0)
                .await
                .expect("memcached set command failed");

            let get_value = socket
                .get(&*key_clone)
                .await
                .expect("memcached get command failed");

            assert_eq!(get_value, value_clone.as_bytes());
        });
    }

    while set.join_next().await.is_some() {}

    info!("Done set memcached value");

    Ok(())
}
