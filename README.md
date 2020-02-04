# CUDA Entrust 2FA Cracker

## Building

The CUDA toolkit must be installed, and `nvcc` should be on the path.

You may need to supply the path to your CUDA libraries directory as an environment variable:

```shell
LIBRARY_PATH="C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v9.1\lib\x64" cargo build
```

Only Linux has been tested, although I think Windows should work fine.

## Future work
* Rewrite the on-GPU part in Rust
* Don't recompute the message schedules for the salt and length on each iteration

## Architecture
`src/backends/cuda/kernal/sha` contains a stripped-down version of [Brian Gladman's PBKDF-HMAC-SHA256 implementation](https://github.com/BrianGladman/sha),
adjusted so it compiles as
CUDA code. The kernel in `src/backends/cuda/kernel/main.cu` will take a code to
start at, and test a block of hashes to see if any of them make sense.
