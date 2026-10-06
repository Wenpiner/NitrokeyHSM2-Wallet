#[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
use {
    crate::transport::Transport,
    anyhow::{anyhow, Result},
    pcsc::{Card, Context, Protocols, Scope, ShareMode},
};

#[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
pub struct PcscTransport {
    context: Option<Context>,
    card: Option<Card>,
    connected: bool,
}

#[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
impl PcscTransport {
    pub fn new() -> Self {
        Self {
            context: None,
            card: None,
            connected: false,
        }
    }
}

#[cfg(all(target_os = "macos", feature = "macos-pcsc"))]
impl Transport for PcscTransport {
    fn name(&self) -> &str {
        "macOS-PCSC-Native"
    }

    fn connect(&mut self) -> Result<()> {
        let ctx = Context::establish(Scope::User)
            .map_err(|e| anyhow!("无法建立 macOS PC/SC 上下文 (智能卡服务可能尚未就绪): {:?}", e))?;

        let mut readers_buf = [0; 2048];
        let readers_iter = ctx.list_readers(&mut readers_buf)
            .map_err(|e| anyhow!("未找到任何智能卡读卡器，请插入 Nitrokey HSM 2: {:?}", e))?;

        let mut matched_reader = None;
        for reader in readers_iter {
            let name_str = reader.to_str().unwrap_or("").to_lowercase();
            if name_str.contains("nitrokey") || name_str.contains("smartcard-hsm") || name_str.contains("cardcontact") || name_str.contains("clay") {
                matched_reader = Some(reader);
                break;
            } else if matched_reader.is_none() {
                matched_reader = Some(reader);
            }
        }

        let reader_name = matched_reader
            .ok_or_else(|| anyhow!("未检测到可用的智能卡读卡器，请插入 Nitrokey HSM 2。"))?;

        let card = ctx.connect(reader_name, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| anyhow!("连接读卡器 {:?} 失败 (卡片未插入或被独占): {:?}", reader_name, e))?;

        self.context = Some(ctx);
        self.card = Some(card);
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<()> {
        self.card = None;
        self.context = None;
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        let card = self.card.as_mut().ok_or_else(|| anyhow!("Card not connected"))?;
        let mut rapdu_buf = [0; 4096];
        let rapdu = card.transmit(apdu, &mut rapdu_buf)
            .map_err(|e| anyhow!("PCSC APDU transmit failed: {:?}", e))?;
        Ok(rapdu.to_vec())
    }
}
