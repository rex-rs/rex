use anyhow::{Context, Result};
use libc::{c_int, c_void, size_t};
use std::ffi::CString;
use std::mem::size_of;
use std::time::SystemTime;

use crate::RexState;
use crate::cli::{Args, StatsType};
use crate::syscall_names::SYSCALL_NAMES;

extern "C" {
    fn get_map_fd(obj: *mut bpf_object, map_name: *const c_char) -> c_int;
    fn lookup_map_value(
        map_fd: c_int,
        key: *const c_void,
        value: *mut c_void,
        value_size: size_t,
    ) -> c_int;
}

pub struct SyscallStat {
    id: u32,
    count: u64,
    errors: u64,
    latency: u64,
}

pub fn print_stats(
    state: &RexState,
    args: &Args,
    start_time: SystemTime,
) -> Result<()> {
    print_header(args.timestamp, args.stats_type());

    let (counts_map_fd, errors_map_fd, latency_map_fd) =
        get_map_fds(state, args.stats_type())?;
    let mut stats =
        collect_stats(counts_map_fd, errors_map_fd, latency_map_fd)?;
    sort_stats(&mut stats, args.sort_by_count());
    let display_stats = limit_stats(&stats, args.top_n);
    print_individual_stats(&display_stats, args, start_time)?;
    print_total_stats(&stats, args, start_time)?;
    println!();

    Ok(())
}
fn get_map_fds(
    state: &RexState,
    stats_type: StatsType,
) -> Result<(c_int, Option<c_int>, Option<c_int>)> {
    let counts_map_fd = get_map_fd_by_name(state.obj, "SYSCALL_COUNTS")?;
    let errors_map_fd =
        if matches!(stats_type, StatsType::ShowErrors | StatsType::ShowBoth) {
            get_map_fd_by_name(state.obj, "SYSCALL_ERRORS").ok()
        } else {
            None
        };
    let latency_map_fd =
        if matches!(stats_type, StatsType::ShowLatency | StatsType::ShowBoth) {
            get_map_fd_by_name(state.obj, "SYSCALL_LATENCY").ok()
        } else {
            None
        };
    Ok((counts_map_fd, errors_map_fd, latency_map_fd))
}

fn collect_stats(
    counts_map_fd: c_int,
    errors_map_fd: Option<c_int>,
    latency_map_fd: Option<c_int>,
) -> Result<Vec<SyscallStat>> {
    let mut stats = Vec::new();
    let mut current_key: Option<u32> = None;
    loop {
        let next_key = get_next_map_key(counts_map_fd, current_key.as_ref())?;
        match next_key {
            Some(key) => {
                let count = lookup_map_value(counts_map_fd, &key)?;
                let errors = errors_map_fd
                    .map(|fd| lookup_map_value(fd, &key).unwrap_or(0))
                    .unwrap_or(0);
                let latency = latency_map_fd
                    .map(|fd| lookup_map_value(fd, &key).unwrap_or(0))
                    .unwrap_or(0);
                stats.push(SyscallStat {
                    id: key,
                    count,
                    errors,
                    latency,
                });
                current_key = Some(key);
            }
            None => break,
        }
    }
    Ok(stats)
}

fn sort_stats(stats: &mut [SyscallStat], sort_by_count: bool) {
    if sort_by_count {
        stats.sort_by(|a, b| b.count.cmp(&a.count));
    } else {
        stats.sort_by(|a, b| a.id.cmp(&b.id));
    }
}

fn limit_stats<'a>(
    stats: &'a [SyscallStat],
    top_n: Option<usize>,
) -> Vec<&'a SyscallStat> {
    if let Some(top_n) = top_n {
        stats.iter().take(top_n).collect()
    } else {
        stats.iter().collect()
    }
}

fn print_total_stats(
    stats: &[SyscallStat],
    args: &Args,
    start_time: SystemTime,
) -> Result<()> {
    let (total_count, total_errors, total_latency) =
        stats.iter().fold((0u64, 0u64, 0u64), |(tc, te, tl), stat| {
            (tc + stat.count, te + stat.errors, tl + stat.latency)
        });
    if args.timestamp {
        let elapsed = SystemTime::now().duration_since(start_time)?.as_secs();
        print!("{:<8} ", elapsed);
    }
    match args.stats_type() {
        StatsType::CountOnly => {
            println!("{:<20} {:<10}", "TOTAL", total_count);
        }
        StatsType::ShowErrors => {
            println!(
                "{:<20} {:<10} {:<10}",
                "TOTAL", total_count, total_errors
            );
        }
        StatsType::ShowLatency => {
            let avg_us = if total_count > 0 {
                total_latency as f64 / total_count as f64 / 1000.0
            } else {
                0.0
            };
            println!("{:<20} {:<10} {:<15.2}", "TOTAL", total_count, avg_us);
        }
        StatsType::ShowBoth => {
            let avg_us = if total_count > 0 {
                total_latency as f64 / total_count as f64 / 1000.0
            } else {
                0.0
            };
            println!(
                "{:<20} {:<10} {:<10} {:<15.2}",
                "TOTAL", total_count, total_errors, avg_us
            );
        }
    }
    Ok(())
}

fn print_individual_stats(
    display_stats: &[&SyscallStat],
    args: &Args,
    start_time: SystemTime,
) -> Result<()> {
    for stat in display_stats {
        let name = if (stat.id as usize) < SYSCALL_NAMES.len() {
            SYSCALL_NAMES[stat.id as usize]
        } else {
            "unknown"
        };
        if args.timestamp {
            let elapsed =
                SystemTime::now().duration_since(start_time)?.as_secs();
            print!("{:<8} ", elapsed);
        }
        match args.stats_type() {
            StatsType::CountOnly => {
                println!("{:<20} {:<10}", name, stat.count);
            }
            StatsType::ShowErrors => {
                println!("{:<20} {:<10} {:<10}", name, stat.count, stat.errors);
            }
            StatsType::ShowLatency => {
                let avg_us = if stat.count > 0 {
                    stat.latency as f64 / stat.count as f64 / 1000.0
                } else {
                    0.0
                };
                println!("{:<20} {:<10} {:<15.2}", name, stat.count, avg_us);
            }
            StatsType::ShowBoth => {
                let avg_us = if stat.count > 0 {
                    stat.latency as f64 / stat.count as f64 / 1000.0
                } else {
                    0.0
                };
                println!(
                    "{:<20} {:<10} {:<10} {:<15.2}",
                    name, stat.count, stat.errors, avg_us
                );
            }
        }
    }
    Ok(())
}
fn get_map_fd_by_name(obj: *mut libc::c_void, name: &str) -> Result<c_int> {
    let c_name =
        CString::new(name).context("Failed to create CString for map name")?;

    let fd = unsafe { get_map_fd(obj, c_name.as_ptr()) };
    if fd < 0 {
        return Err(anyhow::anyhow!("Failed to find map: {}", name));
    }

    Ok(fd)
}

fn print_header(timestamp: bool, stats_type: StatsType) {
    if timestamp {
        print!("{:<8} ", "TIME(s)");
    }

    match stats_type {
        StatsType::CountOnly => println!("{:<20} {:<10}", "SYSCALL", "COUNT"),
        StatsType::ShowErrors => {
            println!("{:<20} {:<10} {:<10}", "SYSCALL", "COUNT", "ERRORS")
        }
        StatsType::ShowLatency => {
            println!("{:<20} {:<10} {:<15}", "SYSCALL", "COUNT", "TIME(us)")
        }
        StatsType::ShowBoth => println!(
            "{:<20} {:<10} {:<10} {:<15}",
            "SYSCALL", "COUNT", "ERRORS", "TIME(us)"
        ),
    }

    if timestamp {
        print!("{:<8} ", "--------");
    }

    match stats_type {
        StatsType::CountOnly => {
            println!("{:<20} {:<10}", "-".repeat(20), "-".repeat(10))
        }
        StatsType::ShowErrors => println!(
            "{:<20} {:<10} {:<10}",
            "-".repeat(20),
            "-".repeat(10),
            "-".repeat(10)
        ),
        StatsType::ShowLatency => println!(
            "{:<20} {:<10} {:<15}",
            "-".repeat(20),
            "-".repeat(10),
            "-".repeat(15)
        ),
        StatsType::ShowBoth => println!(
            "{:<20} {:<10} {:<10} {:<15}",
            "-".repeat(20),
            "-".repeat(10),
            "-".repeat(10),
            "-".repeat(15)
        ),
    }
}
