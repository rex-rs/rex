use std::{thread, time::Duration};

use anyhow::{Ok, Result};
use assert_cmd::{Command, assert::OutputAssertExt};
use duct::{Handle, cmd};
use log::{debug, info};
use tempfile::TempDir;
use test_log::test;

struct ProcessGuard {
    handle: Handle,
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.handle.kill();
        info!("Killed memcached process");
    }
}

#[test]
fn test_memcached_benchmark() -> Result<()> {
    let memcached_port = "11211";

    let memcached_handle =
        cmd!("memcached", "-U", memcached_port, "-v").start()?;

    // Wrap in our guard for automatic cleanup
    let _process_guard = ProcessGuard {
        handle: memcached_handle,
    };

    info!("Started memcached server on port {}", memcached_port);
    thread::sleep(Duration::from_secs(2));

    let temp_dir = TempDir::new()?;
    let dict_path = temp_dir.path().join("test_dict.yml.zst");
    debug!("temp dir path {}", dict_path.display());

    let bin_path =
        std::env::current_exe().expect("Failed to get current exe path");
    debug!("binpath {:?}", bin_path);

    let gen_dict = Command::cargo_bin(env!("CARGO_PKG_NAME"))?
        .args([
            "gen-testdict",
            "--key-size",
            "16",
            "--value-size",
            "32",
            "--dict-entries",
            "10000",
        ])
        .unwrap();

    gen_dict.assert().success();
    info!("Generated test dictionary at: {}", dict_path.display());

    let output = Command::cargo_bin(env!("CARGO_PKG_NAME"))?
        .args([
            "bench",
            "--server-address",
            "localhost",
            "--port",
            memcached_port,
            "--key-size",
            "16",
            "--value-size",
            "32",
            "--nums",
            "50000",
            "--threads",
            "2",
            "--protocol",
            "udp",
            "--dict-entries",
            "10000",
            "--pipeline",
            "100",
        ])
        .output()?;

    output.clone().assert().success();
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;

    debug!("Benchmark stdout: {}", stdout);
    debug!("Benchmark stderr: {}", stderr);

    assert!(stdout.contains("Start set memcached value"));
    assert!(stdout.contains("Throughput across all threads:"));
    assert!(stdout.contains("Done set memcached value"));
    assert!(stdout.contains("Throughput across all threads:"));

    Ok(())
}
