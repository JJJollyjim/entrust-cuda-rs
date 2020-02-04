#include "hmac.c"
#include "itoa.c"
#include "pwd2key.c"
#include "sha2.c"
#include <stdint.h>
#include <stdio.h>



// __device__ const unsigned char data[264] =
//       "action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%"
//       "2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%"
//       "2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%"
//       "2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyP"
//       "LP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1";
// __device__ const unsigned char correctmac[12] = "\x9a\x15K\xf0\x15\x8aj+!1\xae~";
// __device__ unsigned char salt[8] = {0x55, 0x15, 0x2a, 0xe8, 0x8a, 0x0b, 0x59, 0x04};

// Not sure how big this can get (sample I have is 263), being generous with 1024
__device__ const size_t MAX_DATA_SIZE = 1024;
__device__ unsigned char data[MAX_DATA_SIZE] = {0};
__device__ size_t data_size = 0;

__device__ unsigned char correctmac[12] = {0};
__device__ unsigned char salt[8] = {0};


__device__ uint32_t answer = 0xFFFFFFFF;

extern "C" {
__global__ void kern(int base) {
  unsigned char key[32] = {0};
  unsigned char pwdbuf[10] = {0};
  int pwd = base + (blockIdx.x * blockDim.x + threadIdx.x);

  int pwdlen = itoa(pwd, (char *)pwdbuf);
  derive_key(pwdbuf, pwdlen, salt, 8, 1000, key);

  unsigned char hmac[12] = {0};
  hmac_sha(HMAC_SHA256, key, 32, data, data_size, hmac, 12);

  for (int i = 0; i < 12; i++) {
    if (hmac[i] != correctmac[i]) {
      return;
    }
  }
  answer = pwd;
}
}

int main() {
	return 0;
}


