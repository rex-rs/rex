#![allow(clippy::too_many_arguments)]

mod cli;
mod dict;
mod fs;
mod get_values;
mod set_values;

use std::{
    collections::HashMap,
    sync::{Arc, atomic::*},
    vec,
};

use anyhow::{Result, anyhow};
use clap::Parser;
use cli::{Cli, Commands};
use dict::{generate_test_dict_write_to_disk, generate_test_entries};
use env_logger::Target;
use fs::{load_bench_entries_from_disk, load_test_dict, write_hashmap_to_file};
use get_values::{Protocol, get_command_benchmark};
use log::{LevelFilter, info};
use memcache::MemcacheError;
use mimalloc::MiMalloc;
use serde_json::json;
use set_values::set_memcached_value;
use tokio::runtime::Builder;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const BUFFER_SIZE: usize = 1500;
const BENCH_ENTRIES_PATH: &str = "bench_entries.yml.zst";

static TIMEOUT_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_server(
    addr: &String,
    port: &String,
    protocol: &Protocol,
) -> Result<memcache::Client, MemcacheError> {
    match protocol {
        Protocol::Udp => memcache::connect(format!(
            "memcache+udp://{}:{}?timeout=10",
            addr, port
        )),
        Protocol::Tcp => memcache::connect(format!(
            "memcache://{}:{}?timeout=10",
            addr, port
        )),
    }
}

fn run_bench() -> Result<()> {
    let args = Cli::parse();
    let Commands::Bench {
        server_address,
        port,
        key_size,
        value_size,
        validate,
        nums,
        threads,
        protocol,
        dict_path,
        load_bench_entries,
        dict_entries,
        skip_set,
        pipeline,
    } = args.command
    else {
        return Err(anyhow!("invalid command"));
    };

    let server = get_server(&server_address, &port, &protocol)?;

    let test_dict_path = std::path::Path::new(dict_path.as_str());
    let test_dict: HashMap<String, String> = if !test_dict_path.exists() {
        // if dict_path is empty, generate dict
        generate_test_dict_write_to_disk(
            key_size,
            value_size,
            dict_entries,
            dict_path.as_str(),
        )?
    } else {
        load_test_dict(test_dict_path)?
    };
    let test_dict: Arc<HashMap<Arc<String>, Arc<String>>> = Arc::new(
        test_dict
            .into_iter()
            .map(|(k, v)| (Arc::new(k), Arc::new(v)))
            .collect(),
    );

    // if memcached server is already imported, skip set memcached value
    if !skip_set {
        let rt = Builder::new_multi_thread()
            .enable_all()
            .thread_name("memcached-set")
            .event_interval(31)
            .build()?;

        let test_dict = test_dict.clone();
        let server_address = server_address.clone();
        let port = port.clone();
        rt.block_on(async move {
            set_memcached_value(test_dict, server_address, port)
                .await
                .unwrap()
        });
    }

    let test_dict_path = std::path::Path::new(BENCH_ENTRIES_PATH);
    let test_entries_tmp = if load_bench_entries && test_dict_path.exists() {
        load_bench_entries_from_disk(test_dict_path)
    } else {
        vec![]
    };

    info!("Start to generate get commands for each thread");
    let benchmark_entries = if test_entries_tmp.is_empty() {
        let test_entries = generate_test_entries(test_dict.clone(), nums);
        if load_bench_entries {
            let test_entries_write: Vec<(String, String, Protocol)> =
                test_entries
                    .clone()
                    .into_iter() // Iterate over the original vector
                    .map(|(a, b, c)| {
                        (
                            Arc::try_unwrap(a).unwrap_or_else(|a| (*a).clone()),
                            Arc::try_unwrap(b).unwrap_or_else(|b| (*b).clone()),
                            c,
                        )
                    })
                    .collect();

            write_hashmap_to_file(&test_entries_write, BENCH_ENTRIES_PATH)?;
        }
        test_entries
    } else {
        // convert to Vec<(Arc<String>, Arc<String>, Protocol)>
        test_entries_tmp
            .iter()
            .map(|(key, value, proto)| {
                (Arc::new(key.clone()), Arc::new(value.clone()), *proto)
            })
            .collect()
    };
    let benchmark_entries = Arc::new(benchmark_entries);

    // analyze test entries statistics
    // _test_entries_statistics(test_entries.clone());

    let mut send_commands_vec = Vec::new();

    for thread_num in 0..threads {
        let mut seq: u16 = 0;
        let mut send_commands = vec![];

        for index in 0..nums / threads {
            let (key, value, proto) =
                &benchmark_entries[thread_num * nums / threads + index];
            // let packet = wrap_get_command(key.clone(), seq);
            seq = seq.wrapping_add(1);
            send_commands.push((key.clone(), seq, *proto, value.clone()));
        }

        send_commands_vec.push(send_commands);
    }

    let start_time = std::time::SystemTime::now();

    // let rt = Builder::new_multi_thread().enable_all().build()?;
    let mut handles = vec![];
    info!("Start benchmark");

    for tid in 0..threads {
        let test_dict = test_dict.clone();
        let server_address = server_address.clone();
        let port = port.clone();
        let send_commands = send_commands_vec.pop().unwrap();
        let handle = std::thread::Builder::new()
            .name(format!("bmc-worker-{tid}"))
            .spawn(move || {
                let rt =
                    Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move {
                    get_command_benchmark(
                        test_dict,
                        send_commands,
                        server_address,
                        port,
                        validate,
                        key_size,
                        value_size,
                        pipeline,
                    )
                    .await
                    .unwrap();
                    info!("Finish gen_command_bench {}", tid);
                })
            })
            .unwrap();
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // wait for all tasks to complete
    info!("wait for all tasks to complete");

    let elapsed_time = start_time.elapsed()?.as_secs_f64();
    info!("Timeout counter {}", TIMEOUT_COUNTER.load(Ordering::SeqCst));
    let throughput =
        (nums - TIMEOUT_COUNTER.load(Ordering::SeqCst)) as f64 / elapsed_time;
    info!(
        "Throughput across all threads: {:.2} reqs/sec, elapsed_time {}",
        throughput, elapsed_time
    );

    macro_rules! build_stats_map {
    ($result:expr, $($key:expr),*) => {{
        let mut map = ::std::collections::HashMap::new();
        $(
            map.insert($key, &$result[$key]);
        )*
        map
    }};
}

    // stats
    let stats = server.stats()?;
    let result = &stats[0].1;
    let output = build_stats_map!(
        result,
        "cmd_get",
        "cmd_set",
        "get_hits",
        "get_misses",
        "bytes_read",
        "bytes_written",
        "curr_items",
        "total_items"
    );
    let obj = json!(output);
    info!("{}", serde_json::to_string_pretty(&obj).unwrap());
    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();

    env_logger::Builder::new()
        .target(Target::Stdout)
        .filter_level(LevelFilter::Info)
        .init();

    match args.command {
        Commands::Bench { .. } => {
            run_bench()?;
        }
        Commands::GenTestdict {
            key_size,
            value_size,
            dict_entries,
            dict_path,
        } => {
            let _ = generate_test_dict_write_to_disk(
                key_size,
                value_size,
                dict_entries,
                dict_path.as_str(),
            )?;
        }
    }

    Ok(())
}
