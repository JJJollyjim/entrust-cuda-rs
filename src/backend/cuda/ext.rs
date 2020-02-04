use rustacuda::{error::CudaResult, prelude::*};

/// Helper extension trait to read values from rustacuda::module::Symbol and other on-GPU locations
/// TODO: upstream into rustacuda
pub trait CopyDestinationExt<O> {
    fn read(&self) -> CudaResult<O>;
}

impl<O: Default, CD: CopyDestination<O>> CopyDestinationExt<O> for CD {
    fn read(&self) -> CudaResult<O> {
        let mut val = O::default();
        self.copy_to(&mut val)?;
        Ok(val)
    }
}
