use std::{collections::HashMap, mem::size_of_val, sync::Arc};

use log::{debug, info};
use rand::{
    Rng,
    distr::{Alphanumeric, SampleString},
};
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use rand_distr::Zipf;
use rayon::prelude::*;

use crate::{Protocol, fs::write_hashmap_to_file};

const SEED: u64 = 12312;

/// Generate random string of specified length
pub(crate) fn generate_random_str(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
}

/// Generate test dictionary for memcached with random keys and values
pub(crate) fn generate_memcached_test_dict(
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

/// Generate test dict and write to disk
/// # Arguments
/// * `key_size` - key size
/// * `value_size` - value size
/// * `nums` - number of entries
/// * `dict_path` - dict path to store
/// # Returns
/// * `Result` - Result<HashMap<String, String>, anyhow::Error>
/// # Example
/// ```rust
/// let test_dict = generate_test_dict_write_to_disk(16, 32, 100000, "test_dict.yml.zst");
/// ```
pub(crate) fn generate_test_dict_write_to_disk(
    key_size: usize,
    value_size: usize,
    nums: usize,
    dict_path: &str,
) -> anyhow::Result<HashMap<String, String>> {
    let test_dict = generate_memcached_test_dict(key_size, value_size, nums);
    debug!("test dict len: {}", test_dict.len());
    if let Some((key, value)) = test_dict.iter().next() {
        debug!("test dict key size: {}", size_of_val(key.as_str()));
        debug!("test dict value size: {}", size_of_val(value.as_str()));
    } else {
        return Err(anyhow::anyhow!("test dict is empty"));
    }
    write_hashmap_to_file(&test_dict, dict_path)?;
    info!("write test dict to path {}", dict_path);
    Ok(test_dict)
}

/// Generate test entries with Zipf distribution for benchmarking
pub(crate) fn generate_test_entries(
    test_dict: Arc<HashMap<Arc<String>, Arc<String>>>,
    nums: usize,
) -> Vec<(Arc<String>, Arc<String>, Protocol)> {
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    let zipf = Zipf::new((test_dict.len() - 1) as f64, 0.99).unwrap();

    let keys: Vec<Arc<String>> = test_dict.keys().cloned().collect();
    (0..nums)
        .map(|idx| {
            let key = &keys[rng.sample(zipf) as usize];
            let value = test_dict.get(key).unwrap();
            // every 31 element is tcp. udp:tcp = 30:1
            let protocol = if idx % 31 == 30 {
                Protocol::Tcp
            } else {
                Protocol::Udp
            };
            (key.clone(), value.clone(), protocol)
        })
        .collect()
}

/// Analyze the statistics of test entries
#[allow(dead_code)]
pub(crate) fn test_entries_statistics(
    test_entries: Arc<Vec<(&String, &String, Protocol)>>,
) {
    let mut udp_count: usize = 0;
    let mut tcp_count: usize = 0;

    // analyze the key distribution base on the frequency
    let mut key_frequency = HashMap::new();

    // only get the first element in the tuple
    test_entries.iter().for_each(|(key, _, proto)| {
        *key_frequency.entry(key.to_string()).or_insert(0) += 1;
        if *proto == Protocol::Udp {
            udp_count += 1;
        } else {
            tcp_count += 1;
        }
    });

    // sort by frequency
    let mut key_frequency: Vec<_> = key_frequency.into_iter().collect();
    key_frequency.sort_by(|a, b| a.1.cmp(&b.1));

    // Display the frequency of each item
    for (key, count) in &key_frequency {
        if *count < key_frequency.len() / 1000 {
            continue;
        }
        info!("{}: {}", key, count);
    }

    info!("tcp count: {}, udp count: {}", tcp_count, udp_count);
}
