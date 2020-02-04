FROM nvidia/cuda:10.1-runtime-ubuntu18.04
COPY target/release/entrust-cuda-rs /bin
