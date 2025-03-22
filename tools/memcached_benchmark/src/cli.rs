use clap::{Parser, Subcommand};

use crate::Protocol;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    #[command(arg_required_else_help = true)]
    Bench {
        /// memcached server addr
        #[arg(short, long, required = true)]
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
        #[arg(long, default_value = "false")]
        validate: bool,

        /// number of test entries to generate
        #[arg(short, long, default_value = "100000")]
        nums: usize,

        /// number of threads to run
        #[arg(short, long, default_value = "4")]
        threads: usize,

        /// udp or tcp protocol for memcached
        #[arg(short = 'l', long, default_value_t = Protocol::Udp , value_enum)]
        protocol: Protocol,

        /// number of dict entries to generate
        #[arg(short, long, default_value = "1000000")]
        dict_entries: usize,

        /// load the prepared test_entries from disk
        #[arg(long, default_value = "false")]
        load_bench_entries: bool,

        /// skip set memcached value if the data is already imported
        #[arg(long, default_value = "false")]
        skip_set: bool,

        /// bounded mpsc channel for communicating between asynchronous tasks
        /// with backpressure
        #[arg(long, default_value = "200")]
        pipeline: usize,

        /// dict path to load
        #[arg(
            short = 'f',
            long,
            default_value = "test_dict.yml.zst",
            conflicts_with = "key_size",
            conflicts_with = "dict_entries"
        )]
        dict_path: String,
    },
    GenTestdict {
        /// key size to generate random memcached key
        #[arg(short, long, default_value = "16")]
        key_size: usize,

        /// value size to generate random memcached value
        #[arg(short, long, default_value = "32")]
        value_size: usize,

        /// number of dict entries to generate
        #[arg(short, long, default_value = "1000000")]
        dict_entries: usize,

        /// dict path to store
        #[arg(short = 'f', long, default_value = "test_dict.yml.zst")]
        dict_path: String,
    },
}
