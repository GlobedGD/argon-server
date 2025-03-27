use anyhow::{Result, anyhow};
use serde::Serialize;
use serde_json;
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::data::MessageCode;

pub struct NodeConnection {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl NodeConnection {
    pub fn new(stream: TcpStream) -> Self {
        stream.set_nodelay(true).expect("failed to set TCP_NODELAY");

        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    pub async fn send_message<T: Serialize>(&mut self, code: MessageCode, value: &T) -> Result<()> {
        let value = serde_json::to_value(value)?;
        self.send_json_message(code, value).await
    }

    pub async fn send_json_message(
        &mut self,
        code: MessageCode,
        json: serde_json::Value,
    ) -> Result<()> {
        let code = code as u16;

        let data = serde_json::json!({
            "code": code,
            "data": json
        });

        self.send_raw_json(data).await
    }

    pub async fn send_raw_json(&mut self, json: serde_json::Value) -> Result<()> {
        let serialized = json.to_string();
        self._send_data(serialized.as_bytes()).await
    }

    async fn _send_data(&mut self, data: &[u8]) -> Result<()> {
        self.buffer.resize(data.len() + 4, 0);

        self.buffer[..4].copy_from_slice(&(data.len() as u32).to_be_bytes());
        self.buffer[4..4 + data.len()].copy_from_slice(data);

        self.stream
            .write_all(&self.buffer[..4 + data.len()])
            .await?;

        Ok(())
    }
}
