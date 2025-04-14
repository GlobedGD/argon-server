use std::{
    error::Error,
    fmt::Display,
    net::SocketAddr,
    string::FromUtf8Error,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use serde::Serialize;
use serde_json::{self, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex as AsyncMutex,
};

use crate::{
    CryptoBoxError,
    crypto::{CryptoBox, generate_keypair},
    data::MessageCode,
    parse_pubkey,
    logger::*
};

// Send error

#[derive(Debug)]
pub enum SendError {
    Closed,
    Encode(serde_json::Error),
    Socket(std::io::Error),
    Encryption(CryptoBoxError),
}

impl From<serde_json::Error> for SendError {
    fn from(value: serde_json::Error) -> Self {
        Self::Encode(value)
    }
}

impl From<std::io::Error> for SendError {
    fn from(value: std::io::Error) -> Self {
        Self::Socket(value)
    }
}

impl From<CryptoBoxError> for SendError {
    fn from(value: CryptoBoxError) -> Self {
        Self::Encryption(value)
    }
}

impl Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "connection has already been closed"),
            Self::Encode(err) => write!(f, "failed to encode payload: {err}"),
            Self::Socket(err) => write!(f, "IO error during sending data: {err}"),
            Self::Encryption(err) => write!(f, "encryption error: {err}"),
        }
    }
}

impl Error for SendError {}

pub type SendResult<T> = Result<T, SendError>;

// Receive error

#[derive(Debug)]
pub enum ReceiveError {
    Closed,
    Decode(serde_json::Error),
    Socket(std::io::Error),
    InvalidStructure,
    InvalidMessageCode,
    Encryption(CryptoBoxError),
    Unicode(FromUtf8Error),
}

impl From<serde_json::Error> for ReceiveError {
    fn from(value: serde_json::Error) -> Self {
        Self::Decode(value)
    }
}

impl From<std::io::Error> for ReceiveError {
    fn from(value: std::io::Error) -> Self {
        Self::Socket(value)
    }
}

impl From<CryptoBoxError> for ReceiveError {
    fn from(value: CryptoBoxError) -> Self {
        Self::Encryption(value)
    }
}

impl From<FromUtf8Error> for ReceiveError {
    fn from(value: FromUtf8Error) -> Self {
        Self::Unicode(value)
    }
}

impl Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "connection has already been closed"),
            Self::Decode(err) => write!(f, "failed to decode payload: {err}"),
            Self::Socket(err) => write!(f, "IO error during receiving data: {err}"),
            Self::InvalidStructure => write!(f, "invalid message structure was received"),
            Self::InvalidMessageCode => write!(f, "invalid message code was received"),
            Self::Encryption(err) => write!(f, "encryption error: {err}"),
            Self::Unicode(err) => write!(f, "utf-8 decoding error: {err}"),
        }
    }
}

impl Error for ReceiveError {}

pub type ReceiveResult<T> = Result<T, ReceiveError>;

pub struct ReceivedMessage {
    pub code: MessageCode,
    pub data: serde_json::Value,
}

// General error

#[derive(Debug)]
pub enum HandshakeError {
    Send(SendError),
    Receive(ReceiveError),
    UnexpectedMessage,
    InvalidPubkey,
}

impl From<SendError> for HandshakeError {
    fn from(value: SendError) -> Self {
        Self::Send(value)
    }
}

impl From<ReceiveError> for HandshakeError {
    fn from(value: ReceiveError) -> Self {
        Self::Receive(value)
    }
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Send(e) => write!(f, "{e}"),
            Self::Receive(e) => write!(f, "{e}"),
            Self::UnexpectedMessage => write!(
                f,
                "unexpected message arrived when waiting for handshake response"
            ),
            Self::InvalidPubkey => write!(f, "server sent an invalid public key"),
        }
    }
}

impl Error for HandshakeError {}

// Node connection

pub struct NodeConnection {
    stream_write: AsyncMutex<OwnedWriteHalf>,
    stream_read: AsyncMutex<OwnedReadHalf>,
    buffer: AsyncMutex<Vec<u8>>,
    is_valid_: AtomicBool,
    crypto_box: AsyncMutex<Option<CryptoBox>>,
}

impl NodeConnection {
    pub fn new(stream: TcpStream) -> Self {
        stream.set_nodelay(true).expect("failed to set TCP_NODELAY");
        stream
            .set_linger(Some(Duration::from_secs(1)))
            .expect("failed to set SO_LINGER");

        let (read, write) = stream.into_split();

        Self {
            stream_write: AsyncMutex::new(write),
            stream_read: AsyncMutex::new(read),
            buffer: AsyncMutex::new(Vec::new()),
            is_valid_: AtomicBool::new(true),
            crypto_box: AsyncMutex::new(None),
        }
    }

    pub async fn close(&self) -> std::io::Result<()> {
        self._invalidate();
        self.stream_write.lock().await.shutdown().await
    }

    pub fn is_valid(&self) -> bool {
        self.is_valid_.load(Ordering::SeqCst)
    }

    fn _invalidate(&self) {
        self.is_valid_.store(false, Ordering::SeqCst);
    }

    pub async fn peer_address(&self) -> std::io::Result<SocketAddr> {
        self.stream_write.lock().await.peer_addr()
    }

    /// Perform the crypto handshake (node-side)
    pub async fn perform_handshake(&self) -> Result<(), HandshakeError> {
        let (secret_key, public_key) = generate_keypair();

        let pubkey = hex::encode(public_key.to_bytes());

        self.send_message(MessageCode::NodeHandshake, &pubkey)
            .await?;

        let msg = self.receive_message().await?;

        if msg.code != MessageCode::HandshakeResponse {
            return Err(HandshakeError::UnexpectedMessage);
        }

        let server_pubkey = match msg.data.as_str() {
            Some(x) => parse_pubkey(x).ok_or(HandshakeError::InvalidPubkey),
            None => Err(HandshakeError::InvalidPubkey),
        }?;

        let crypto_box = CryptoBox::new_shared(&server_pubkey, &secret_key);

        *self.crypto_box.lock().await = Some(crypto_box);

        Ok(())
    }

    /// Wait for the client to perform a handshake (server-side)
    pub async fn wait_for_handshake(&self) -> Result<(), HandshakeError> {
        let (secret_key, public_key) = generate_keypair();

        // wait for the crypto handshake packet

        let msg = self.receive_message().await?;
        if msg.code != MessageCode::NodeHandshake {
            return Err(HandshakeError::UnexpectedMessage);
        }

        let node_pubkey = match msg.data.as_str() {
            Some(x) => parse_pubkey(x).ok_or(HandshakeError::InvalidPubkey),
            None => Err(HandshakeError::InvalidPubkey),
        }?;

        // send them our pubkey
        self.send_message(
            MessageCode::HandshakeResponse,
            &hex::encode(public_key.to_bytes()),
        )
        .await?;

        // initialize crypto box
        let crypto_box = CryptoBox::new_shared(&node_pubkey, &secret_key);

        *self.crypto_box.lock().await = Some(crypto_box);

        Ok(())
    }

    /// Send a message to the peer with the given code and data. Data must implement `serde::Serialize`
    pub async fn send_message<T: Serialize>(&self, code: MessageCode, value: &T) -> SendResult<()> {
        let value = serde_json::to_value(value)?;
        self.send_json_message(code, value).await
    }

    /// Send a message to the peer with the given code and data being null.
    pub async fn send_message_code(&self, code: MessageCode) -> SendResult<()> {
        self.send_json_message(code, Value::Null).await
    }

    /// Send a message to the peer with the given code and JSON data.
    pub async fn send_json_message(&self, code: MessageCode, json: Value) -> SendResult<()> {
        let code = code as u16;

        let data = serde_json::json!({
            "code": code,
            "data": json
        });

        self.send_raw_json(data).await
    }

    /// Serialize the given JSON data into a string and send it to the peer
    pub async fn send_raw_json(&self, json: Value) -> SendResult<()> {
        let serialized = json.to_string();
        self._send_data(serialized.as_bytes()).await
    }

    /// Send the raw bytes to the peer (encrypted, then length prefixed)
    async fn _send_data(&self, data: &[u8]) -> SendResult<()> {
        if !self.is_valid() {
            return Err(SendError::Closed);
        }

        let crypto_box = self.crypto_box.lock().await;

        // if we have already performed the handshake, we should encrypt this data
        let encrypted_vec: Vec<u8>;
        let data = match crypto_box.as_ref() {
            Some(crypto_box) => {
                encrypted_vec = crypto_box.encrypt(data)?;
                &encrypted_vec[..]
            }

            None => data,
        };

        let mut buffer = self.buffer.lock().await;

        // grow buffer if needed
        let full_buf_size = data.len() + 4;
        if buffer.len() < full_buf_size {
            buffer.resize(full_buf_size, 0);
        }

        buffer[..4].copy_from_slice(&(data.len() as u32).to_be_bytes());
        buffer[4..full_buf_size].copy_from_slice(data);

        let mut stream = self.stream_write.lock().await;
        stream.write_all(&buffer[..full_buf_size]).await?;

        Ok(())
    }

    /// Blocks until data is available
    pub async fn poll_for_msg(&self) -> ReceiveResult<()> {
        let mut stream = self.stream_read.lock().await;

        let mut buf = [0u8; 4];

        loop {
            let b = stream.peek(&mut buf).await?;

            if b == 0 {
                return Err(ReceiveError::Closed);
            }

            if b == 4 {
                break;
            }
        }

        Ok(())
    }

    /// Receive a message from the peer, blocks until one is available
    pub async fn receive_message(&self) -> ReceiveResult<ReceivedMessage> {
        if !self.is_valid() {
            return Err(ReceiveError::Closed);
        }

        // for some reason, this literally does not work on windows, it just blocks forever
        // we don't *really* need it anyway, but in case `receive_message` gets cancelled,
        // the read_u32 call below may have already read some bytes, and it will leave this connection in an inconsistent state
        // of course, the chances of this happening are super slim, but we add this poll just in case.
        #[cfg(not(windows))]
        self.poll_for_msg().await?;

        let mut stream = self.stream_read.lock().await;

        let length = stream.read_u32().await? as usize;

        let mut buffer = self.buffer.lock().await;

        if buffer.len() < length {
            buffer.resize(length, 0);
        }

        stream.read_exact(&mut buffer[..length]).await?;

        let crypto_box = self.crypto_box.lock().await;

        // if we have already performed the handshake, we should decrypt this data
        let json_string = match crypto_box.as_ref() {
            Some(crypto_box) => {
                let dec_vec = crypto_box.decrypt(&buffer[..length])?;
                String::from_utf8(dec_vec)
            }

            None => String::from_utf8(buffer[..length].to_owned()),
        }?;

        let value = json_string.parse::<Value>()?;

        Self::_message_from_json(value)
    }

    fn _message_from_json(mut value: Value) -> ReceiveResult<ReceivedMessage> {
        let code = value
            .get("code")
            .and_then(|x| x.as_u64())
            .ok_or(ReceiveError::InvalidStructure)?;

        let code = u16::try_from(code)
            .ok()
            .and_then(|x| MessageCode::try_from(x).ok())
            .ok_or(ReceiveError::InvalidMessageCode)?;

        let data = value
            .get_mut("data")
            .ok_or(ReceiveError::InvalidStructure)?;

        Ok(ReceivedMessage {
            code,
            data: data.take(),
        })
    }
}
