mod cuda;
pub use cuda::CudaBackend;

pub trait Crack {
    fn hack(
        salt: [u8; 8],
        correct_mac: [u8; 12],
        payload: &[u8],
        progress: indicatif::ProgressBar,
    ) -> Option<u32>;
}
