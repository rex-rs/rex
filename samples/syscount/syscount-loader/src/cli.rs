use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum StatsType {
    CountOnly,
    ShowErrors,
    ShowLatency,
    ShowBoth,
}

#[derive(Parser, Debug)]
#[command(
    name = "syscount-rs",
    about = "Traces system calls and reports statistics",
    version
)]
pub struct Args {
    /// Set the output interval in seconds
    #[arg(short = 'i', long, default_value = "1")]
    pub interval: u64,

    /// Include timestamp in output
    #[arg(short, long)]
    pub timestamp: bool,

    /// Clear the screen between outputs
    #[arg(short = 'c', long)]
    pub clear_screen: bool,

    /// Sort by syscall name instead of count
    #[arg(short = 's', long)]
    pub sort_by_name: bool,

    /// Display only the top N syscalls
    #[arg(short = 'n', long)]
    pub top_n: Option<usize>,

    /// Show errors count
    #[arg(short = 'e', long)]
    pub show_errors: bool,

    /// Show latency (average time per syscall in microseconds)
    #[arg(short = 'l', long)]
    pub show_latency: bool,

    /// Filter by process ID
    #[arg(short = 'p', long)]
    pub pid: Option<i32>,

    /// Trace only comma-separated syscalls
    #[arg(short = 'x', long, value_delimiter = ',')]
    pub syscalls: Option<Vec<String>>,

    /// Path to the BPF program
    #[arg(
        long,
        default_value = "./target/x86_64-unknown-none/release/syscount"
    )]
    pub bpf_path: PathBuf,
}

impl Args {
    pub fn stats_type(&self) -> StatsType {
        match (self.show_errors, self.show_latency) {
            (true, true) => StatsType::ShowBoth,
            (true, false) => StatsType::ShowErrors,
            (false, true) => StatsType::ShowLatency,
            (false, false) => StatsType::CountOnly,
        }
    }
}

pub fn parse_args() -> Args {
    Args::parse()
}
