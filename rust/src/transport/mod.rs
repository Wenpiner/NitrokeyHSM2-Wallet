pub mod mock;

#[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
pub mod pcsc;

pub mod android;

use anyhow::Result;

/// 跨端硬件通信抽象
pub trait Transport: Send + Sync {
    fn name(&self) -> &str;
    fn connect(&mut self) -> Result<()>;
    fn disconnect(&mut self) -> Result<()>;
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
    fn is_connected(&self) -> bool;
}
