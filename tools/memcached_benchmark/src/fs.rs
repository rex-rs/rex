use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::Result;
use log::{debug, info};
use serde::Serialize;

use crate::Protocol;

/// Write hashmap to a compressed file using zstd
/// # Arguments
/// * `hashmap` - hashmap to write to file
/// * `file_path` - file path to write
/// # Returns
/// * `Result` - Result<(), anyhow::Error>
pub(crate) fn write_hashmap_to_file<T: Serialize>(
    hashmap: &T,
    file_path: &str,
) -> Result<()> {
    // Serialize the hashmap to a YAML string
    let serialized =
        serde_yaml::to_string(hashmap).expect("Failed to serialize");

    // Create or open the file
    let file = File::create(file_path)?;

    // Create a zstd encoder with compression level 7
    let mut encoder = zstd::stream::write::Encoder::new(file, 7)?;

    // Write the YAML string to the file
    encoder.write_all(serialized.as_bytes())?;
    encoder.finish()?;

    Ok(())
}

/// Loads benchmark entries from disk from a zstd-compressed YAML file.
///
/// Although the entries are typically selected randomly from a test dictionary,
/// there are cases where a fixed sequence of entries is needed to ensure
/// consistent performance comparisons, and this function is utilized to
/// retrieve the stored benchmark entries
pub(crate) fn load_bench_entries_from_disk(
    path: &Path,
) -> Vec<(String, String, Protocol)> {
    let file = std::fs::File::open(path).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    let reader = std::io::BufReader::new(decoder);
    let test_entries: Vec<(String, String, Protocol)> =
        serde_yaml::from_reader(reader).unwrap();
    test_entries
}

/// Load test dictionary from disk
///
/// This function opens a file located at `test_dict_path`, which is expected to
/// be a zstd-compressed and valid YAML document key-value pair
/// (`HashMap<String, String>`).
pub(crate) fn load_test_dict(
    test_dict_path: &std::path::Path,
) -> anyhow::Result<HashMap<String, String>> {
    // load dict from file if dict_path is not empty
    info!("loading dict from path {:?}", test_dict_path);
    let file = std::fs::File::open(test_dict_path)?;
    let decoder = zstd::stream::read::Decoder::new(file)?;
    let reader = BufReader::new(decoder);

    // Deserialize the string into a HashMap
    let mut test_dict = HashMap::new();

    reader.lines().for_each(|line| {
        let line = line.unwrap();
        // Assuming each line in your file is a valid YAML representing a
        // key-value pair
        let deserialized_map: HashMap<String, String> =
            serde_yaml::from_str(&line).unwrap();
        test_dict.extend(deserialized_map);
    });

    debug!("test dict len: {}", test_dict.len());
    if let Some(key) = test_dict.keys().next() {
        debug!("test dict key size: {}", key.len());
    }
    if let Some(value) = test_dict.values().next() {
        debug!("test dict value size: {}", value.len());
    }
    Ok(test_dict)
}
