#![feature(exit_status_error)]

use std::io::Result;
use std::path::Path;
use std::process::Command;
use std::string::String;
use std::{env, fs};

fn main() -> Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let linux_obj = env::var("LINUX_OBJ").unwrap();
    let linux_src = env::var("LINUX_SRC").unwrap();

    let output = Command::new("python3")
        .arg("build.py")
        .arg(&linux_obj)
        .arg(&linux_src)
        .arg(&out_dir)
        .output()?;

    output
        .status
        .exit_ok()
        .map(|_| print!("{}", String::from_utf8_lossy(&output.stdout)))
        .map_err(|_| panic!("\n{}", String::from_utf8_lossy(&output.stderr)))
        .unwrap();

    let mut rexstub_outdir = Path::new(&out_dir).join("librexstub");
    if !rexstub_outdir.exists() {
        fs::create_dir(&rexstub_outdir)?;
    }

    let rexstub_so = rexstub_outdir.join("librexstub.so");
    Command::new("clang")
        .arg("-fPIC")
        .arg("-nostartfiles")
        .arg("-nodefaultlibs")
        .arg("--shared")
        .arg("-o")
        .arg(rexstub_so.to_string_lossy().to_mut())
        .arg("./librexstub/lib.c")
        .output()?;

    rexstub_outdir = rexstub_outdir.canonicalize()?;

    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=./src/*");
    println!("cargo:rerun-if-changed=./librexstub/*");
    println!("cargo:rustc-link-lib=dylib=rexstub");
    println!(
        "cargo:rustc-link-search=native={}",
        rexstub_outdir.to_string_lossy()
    );

    Ok(())
}
