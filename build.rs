use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    // rustacuda doesn't search common CUDA installation paths
    println!(r"cargo:rustc-link-search=/opt/cuda/targets/x86_64-linux/lib");

    println!(r"cargo:rustc-link-search=/usr/local/cuda-10.0/targets/x86_64-linux/lib");
    println!(r"cargo:rustc-link-search=/usr/local/cuda-10.1/targets/x86_64-linux/lib");
    println!(r"cargo:rustc-link-search=/usr/local/cuda-10.2/targets/x86_64-linux/lib");

    println!(r"cargo:rustc-link-search=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v10.0");
    println!(r"cargo:rustc-link-search=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v10.1");
    println!(r"cargo:rustc-link-search=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v10.2");

    let src_dir: PathBuf = "src/backend/cuda/kernel".parse().unwrap();

    let mut ptx_file: PathBuf = env::var("OUT_DIR").unwrap().parse().unwrap();
    ptx_file.push("kernel.ptx");

    println!("cargo:rerun-if-env-changed=ENTRUST_KERNEL_PTX");

    if env::var("ENTRUST_KERNEL_PTX").is_err() {
        let status = Command::new("nvcc")
            .arg("-I")
            .arg(&src_dir.join("sha"))
            .arg(&src_dir.join("main.cu"))
            .arg("--ptx")
            .arg("-o")
            .arg(&ptx_file)
            .status()
            .expect("couldn't run nvcc");

        println!("cargo:rerun-if-changed={}", src_dir.to_str().unwrap());
        for ent in fs::read_dir(&src_dir).unwrap() {
            println!(
                "cargo:rerun-if-changed={}",
                ent.unwrap().path().to_str().unwrap()
            );
        }

        if status.success() {
            println!(
                "cargo:rustc-env=ENTRUST_KERNEL_PTX={}",
                ptx_file.to_str().unwrap()
            );
        } else {
            panic!("nvcc failed with exit code {}", status);
        }
    }
}
