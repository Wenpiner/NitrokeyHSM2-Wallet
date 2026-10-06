use anyhow::{anyhow, Result};
use crate::transport::Transport;

pub type UsbTransmitCallback = Box<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync>;

/// Android USB CCID 传输管道
/// 与 Android 原生层的 UsbCcidPlugin 进行 JNI 桥接
pub struct AndroidUsbTransport {
    transmit_callback: Option<UsbTransmitCallback>,
    connected: bool,
}

impl AndroidUsbTransport {
    pub fn new() -> Self {
        Self {
            transmit_callback: None,
            connected: false,
        }
    }

    /// 注入由 Android Kotlin 层提供的 USB CCID 收发句柄
    pub fn register_callback(&mut self, cb: UsbTransmitCallback) {
        self.transmit_callback = Some(cb);
        self.connected = true;
    }
}

impl Default for AndroidUsbTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for AndroidUsbTransport {
    fn name(&self) -> &str {
        "Android-USB-CCID-Transport"
    }

    fn connect(&mut self) -> Result<()> {
        if self.transmit_callback.is_none() {
            return Err(anyhow!("Android USB callback not registered yet"));
        }
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        if let Some(cb) = &self.transmit_callback {
            cb(apdu)
        } else {
            Err(anyhow!("No active Android USB connection"))
        }
    }
}
