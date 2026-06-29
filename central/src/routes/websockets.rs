use std::{io::Cursor, net::IpAddr, sync::Arc};

use argon_shared::logger::*;
use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};
use rocket::{
    State,
    futures::{SinkExt, StreamExt},
    get,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    api_token_manager::{ApiTokenManager, TokenFetchError},
    database::ArgonDbPool,
    health_state::{ServerHealthState, ServerStatusResponse},
    routes::validation::{
        MAX_USERS_IN_REQUEST, StrongUserAuthData, StrongValidationResponse, UserAuthData, UserCheckResponse,
        ValidationResponse, WithId, validate_one_check, validate_one_strong, validate_one_weak,
    },
    token_issuer::TokenIssuer,
};

use super::routes_util::CloudflareIPGuard;
use rocket_ws::{self as ws, stream::DuplexStream};

const MSG_AUTH: u8 = 1;
const MSG_AUTH_ACK: u8 = 2;
const MSG_FATAL_ERROR: u8 = 3;
const MSG_ERROR: u8 = 4;
const MSG_STATUS: u8 = 5;
const MSG_STATUS_RESPONSE: u8 = 6;
const MSG_VALIDATE: u8 = 7;
const MSG_VALIDATE_RESPONSE: u8 = 8;
const MSG_VALIDATE_STRONG: u8 = 9;
const MSG_VALIDATE_STRONG_RESPONSE: u8 = 10;
const MSG_VALIDATE_CHECK_DATA_MANY: u8 = 13;
const MSG_VALIDATE_CHECK_DATA_MANY_RESPONSE: u8 = 14;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
enum WsProtocol {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "json-zstd")]
    JsonZstd,
    #[serde(rename = "binary-v1")]
    Binary,
}

#[derive(Debug, Error)]
enum HandleError {
    #[error("Cannot perform this action while unauthorized")]
    Unauthorized,
    #[error("Invalid API token provided, please read the WebSockets section in the server documentation")]
    InvalidAuth,
    #[error("Invalid or malformed request received: {0}")]
    InvalidRequest(&'static str),
    #[error("Failed to serialize/deserialize response: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Failed to decode binary response: {0}")]
    BinaryDecode(#[from] TryGetError),
    #[error("Failed to compress response: {0}")]
    Compression(std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AuthMessage {
    token: String,
    proto: WsProtocol,
}

#[derive(Deserialize, Debug, Clone)]
struct ValidateMessage {
    items: Vec<UserAuthData>,
}

#[derive(Serialize, Debug, Clone)]
struct ValidateResponseMessage {
    items: Vec<WithId<ValidationResponse>>,
}

#[derive(Deserialize, Debug, Clone)]
struct ValidateStrongMessage {
    items: Vec<StrongUserAuthData>,
}

#[derive(Serialize, Debug, Clone)]
struct ValidateStrongResponseMessage {
    items: Vec<WithId<StrongValidationResponse>>,
}

#[derive(Deserialize, Debug, Clone)]
struct ValidateCheckDataManyMessage {
    items: Vec<UserAuthData>,
}

#[derive(Serialize, Debug, Clone)]
struct ValidateCheckDataManyResponseMessage {
    items: Vec<WithId<UserCheckResponse>>,
}

enum ClientMessage {
    Auth(AuthMessage),
    Status,
    Validate(ValidateMessage),
    ValidateStrong(ValidateStrongMessage),
    ValidateCheckDataMany(ValidateCheckDataManyMessage),
}

impl ClientMessage {
    pub fn decode_json(msg: &Value) -> Result<Self, HandleError> {
        let r#type = msg["type"]
            .as_str()
            .ok_or(HandleError::InvalidRequest("missing or invalid type"))?;

        match r#type {
            "Auth" => {
                let data: AuthMessage = serde_json::from_value(msg["data"].clone())?;
                Ok(ClientMessage::Auth(data))
            }

            "Status" => Ok(ClientMessage::Status),

            "Validate" => {
                let items: Vec<UserAuthData> = serde_json::from_value(msg["data"].clone())?;
                Ok(ClientMessage::Validate(ValidateMessage { items }))
            }

            "ValidateStrong" => {
                let items: Vec<StrongUserAuthData> = serde_json::from_value(msg["data"].clone())?;
                Ok(ClientMessage::ValidateStrong(ValidateStrongMessage { items }))
            }

            "ValidateCheckDataMany" => {
                let items: Vec<UserAuthData> = serde_json::from_value(msg["data"].clone())?;
                Ok(ClientMessage::ValidateCheckDataMany(
                    ValidateCheckDataManyMessage { items },
                ))
            }

            _ => Err(HandleError::InvalidRequest("unknown message type")),
        }
    }

    pub fn decode_binary(data: &[u8]) -> Result<Self, HandleError> {
        let mut buf = Bytes::copy_from_slice(data);
        let msg_type = buf.try_get_u8()?;

        match msg_type {
            MSG_AUTH => Err(HandleError::InvalidRequest("Auth message can only be json")),

            MSG_STATUS => Ok(Self::Status),

            MSG_VALIDATE => {
                let items = Self::read_vec(&mut buf, |b| {
                    let account_id = b.try_get_i32_le()?;
                    let token = Self::read_string(b)?;

                    Ok(UserAuthData { account_id, token })
                })?;

                Ok(Self::Validate(ValidateMessage { items }))
            }

            MSG_VALIDATE_STRONG => {
                let elems = Self::read_vec(&mut buf, |b| {
                    let account_id = b.try_get_i32_le()?;
                    let user_id = if b.try_get_u8()? != 0 {
                        Some(b.try_get_i32_le()?)
                    } else {
                        None
                    };

                    let name = if b.try_get_u8()? != 0 {
                        Some(Self::read_string(b)?)
                    } else {
                        None
                    };

                    let token = Self::read_string(b)?;

                    Ok(StrongUserAuthData {
                        account_id,
                        token,
                        name,
                        user_id,
                    })
                })?;

                Ok(ClientMessage::ValidateStrong(ValidateStrongMessage {
                    items: elems,
                }))
            }

            MSG_VALIDATE_CHECK_DATA_MANY => {
                let elems = Self::read_vec(&mut buf, |b| {
                    let account_id = b.try_get_i32_le()?;
                    let token = Self::read_string(b)?;

                    Ok(UserAuthData { account_id, token })
                })?;

                Ok(ClientMessage::ValidateCheckDataMany(
                    ValidateCheckDataManyMessage { items: elems },
                ))
            }

            _ => Err(HandleError::InvalidRequest("unknown message type")),
        }
    }

    fn read_string(buf: &mut Bytes) -> Result<String, HandleError> {
        let len = buf.try_get_u16_le()? as usize;

        if buf.remaining() < len {
            return Err(HandleError::InvalidRequest("not enough bytes for string"));
        }

        let str_data = buf.copy_to_bytes(len);
        Ok(String::from_utf8_lossy(&str_data).to_string())
    }

    fn read_vec<T, F: Fn(&mut Bytes) -> Result<T, HandleError>>(
        bytes: &mut Bytes,
        decode_fn: F,
    ) -> Result<Vec<T>, HandleError> {
        let length = bytes.try_get_u16_le()? as usize;
        let mut output = Vec::new();

        for _ in 0..length {
            output.push(decode_fn(bytes)?);
        }

        Ok(output)
    }
}

enum ServerMessage {
    FatalError(String),
    Error(String),
    AuthAck,
    StatusResponse(ServerStatusResponse),
    ValidateResponse(ValidateResponseMessage),
    ValidateStrongResponse(ValidateStrongResponseMessage),
    ValidateCheckDataManyResponse(ValidateCheckDataManyResponseMessage),
}

impl ServerMessage {
    pub fn numeric_id(&self) -> u8 {
        match self {
            ServerMessage::FatalError(_) => MSG_FATAL_ERROR,
            ServerMessage::Error(_) => MSG_ERROR,
            ServerMessage::AuthAck => MSG_AUTH_ACK,
            ServerMessage::StatusResponse(_) => MSG_STATUS_RESPONSE,
            ServerMessage::ValidateResponse(_) => MSG_VALIDATE_RESPONSE,
            ServerMessage::ValidateStrongResponse(_) => MSG_VALIDATE_STRONG_RESPONSE,
            ServerMessage::ValidateCheckDataManyResponse(_) => MSG_VALIDATE_CHECK_DATA_MANY_RESPONSE,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            ServerMessage::FatalError(_) => "FatalError",
            ServerMessage::Error(_) => "Error",
            ServerMessage::AuthAck => "AuthAck",
            ServerMessage::StatusResponse(_) => "StatusResponse",
            ServerMessage::ValidateResponse(_) => "ValidateResponse",
            ServerMessage::ValidateStrongResponse(_) => "ValidateStrongResponse",
            ServerMessage::ValidateCheckDataManyResponse(_) => "ValidateCheckDataManyResponse",
        }
    }

    pub fn encode_json(&self) -> Result<Value, HandleError> {
        Ok(match self {
            ServerMessage::AuthAck => serde_json::Value::Null,
            ServerMessage::StatusResponse(msg) => serde_json::to_value(msg)?,

            ServerMessage::ValidateResponse(msg) => serde_json::to_value(&msg.items)?,
            ServerMessage::ValidateStrongResponse(msg) => serde_json::to_value(&msg.items)?,
            ServerMessage::ValidateCheckDataManyResponse(msg) => serde_json::to_value(&msg.items)?,

            ServerMessage::FatalError(msg) | ServerMessage::Error(msg) => {
                serde_json::json!({ "error": msg })
            }
        })
    }

    pub fn encode_binary(&self, buf: &mut BytesMut) {
        match &self {
            &Self::AuthAck => {}
            &Self::Error(e) | &Self::FatalError(e) => {
                Self::write_string(buf, e);
            }

            &Self::StatusResponse(r) => {
                buf.put_u8(r.active as u8);
                buf.put_i32_le(r.total_nodes as i32);
                buf.put_i32_le(r.active_nodes as i32);
                Self::write_string(buf, &r.ident);
            }

            &Self::ValidateResponse(r) => {
                buf.put_u16_le(r.items.len() as u16);

                for item in &r.items {
                    buf.put_i32_le(item.id);
                    buf.put_u8(item.value.valid as u8);

                    if let Some(cause) = &item.value.cause {
                        Self::write_string(buf, cause);
                    }
                }
            }

            &Self::ValidateStrongResponse(r) => {
                buf.put_u16_le(r.items.len() as u16);
                for item in &r.items {
                    buf.put_i32_le(item.id);
                    buf.put_u8(item.value.valid as u8);
                    buf.put_u8(item.value.valid_weak as u8);

                    if let Some(cause) = &item.value.cause {
                        assert!(!item.value.valid);
                        Self::write_string(buf, cause);
                    }

                    if let Some(username) = &item.value.username {
                        assert!(item.value.valid);
                        Self::write_string(buf, username);
                    }
                }
            }

            &Self::ValidateCheckDataManyResponse(r) => {
                buf.put_u16_le(r.items.len() as u16);
                for item in &r.items {
                    buf.put_i32_le(item.id);
                    buf.put_u8(item.value.valid as u8);

                    if let Some(cause) = &item.value.cause {
                        assert!(!item.value.valid);
                        Self::write_string(buf, cause);
                    } else {
                        assert!(item.value.valid);
                        let user_id = item.value.user_id.unwrap_or(0);
                        buf.put_i32_le(user_id);
                        Self::write_string(buf, item.value.username.as_deref().unwrap_or(""));
                    }
                }
            }
        }
    }

    fn write_string(buf: &mut BytesMut, s: &str) {
        let bytes = s.as_bytes();
        buf.put_u16_le(bytes.len() as u16);
        buf.put_slice(bytes);
    }
}

struct ClientConnection {
    protocol: WsProtocol,
    token_id: Option<i32>,
    token_manager: Arc<ApiTokenManager>,
    health_state: Arc<ServerHealthState>,
    token_issuer: Arc<TokenIssuer>,
    db_pool: Arc<ArgonDbPool>,
    user_ip: IpAddr,
    stream: DuplexStream,
    closed: bool,
}

impl ClientConnection {
    pub async fn run_loop(&mut self) -> anyhow::Result<()> {
        while !self.closed
            && let Some(msg) = self.stream.next().await
        {
            let msg = msg?;
            if msg.is_ping() {
                continue;
            }

            let msg = match decode_message(&msg, self.protocol) {
                Ok(m) => m,
                Err(e) => {
                    let msg = self.fatal_error(&e.to_string())?;
                    self.stream.send(msg).await?;
                    break;
                }
            };

            let message = match self.handle_message(msg).await {
                Ok(msg) => encode_message(&msg, self.protocol)?,

                Err(err @ HandleError::Unauthorized) | Err(err @ HandleError::InvalidAuth) => {
                    // fatal error
                    self.fatal_error(&err.to_string())?
                }

                Err(err) => {
                    warn!("[{}] error handling ws message: {err}", self.user_ip);
                    encode_error(&err.to_string(), self.protocol)?
                }
            };

            self.stream.send(message).await?;
        }

        Ok(())
    }

    fn fatal_error(&mut self, msg: &str) -> Result<ws::Message, HandleError> {
        self.closed = true;
        encode_fatal_error(msg, self.protocol)
    }

    pub async fn handle_message(&mut self, msg: ClientMessage) -> Result<ServerMessage, HandleError> {
        // if unauthorized, first message must be an authentication request
        if self.token_id.is_none() {
            self.try_authenticate(&msg).await?;
            return Ok(ServerMessage::AuthAck);
        }

        Ok(match msg {
            ClientMessage::Status => ServerMessage::StatusResponse(self.health_state.status()),

            ClientMessage::Validate(m) => self.validate_weak(&m.items).await?,
            ClientMessage::ValidateStrong(m) => self.validate_strong(&m.items).await?,
            ClientMessage::ValidateCheckDataMany(m) => self.validate_check_data(&m.items).await?,

            ClientMessage::Auth(_) => ServerMessage::Error("Already authenticated".to_owned()),
        })
    }

    async fn try_authenticate(&mut self, msg: &ClientMessage) -> Result<(), HandleError> {
        let ClientMessage::Auth(msg) = msg else {
            return Err(HandleError::Unauthorized);
        };

        self.token_id = Some(self.token_manager.validate_api_token(&msg.token).map_err(|err| {
            warn!("[{}] Failed to validate API token: {err}", self.user_ip);
            HandleError::InvalidAuth
        })?);

        self.protocol = msg.proto;

        Ok(())
    }

    async fn validate_weak(&mut self, items: &[UserAuthData]) -> Result<ServerMessage, HandleError> {
        if let Err(e) = self.validate_req(items.len()).await {
            return Err(HandleError::Other(e));
        }

        // finally, validate the tokens
        let mut response = ValidateResponseMessage {
            items: Vec::with_capacity(items.len()),
        };

        for account in items {
            let res = validate_one_weak(
                &self.token_issuer,
                self.user_ip,
                account.account_id,
                &account.token,
            );

            response.items.push(WithId {
                id: account.account_id,
                value: res,
            });
        }

        Ok(ServerMessage::ValidateResponse(response))
    }

    async fn validate_strong(&mut self, items: &[StrongUserAuthData]) -> Result<ServerMessage, HandleError> {
        if let Err(e) = self.validate_req(items.len()).await {
            return Err(HandleError::Other(e));
        }

        // finally, validate the tokens
        let mut response = ValidateStrongResponseMessage {
            items: Vec::with_capacity(items.len()),
        };

        for account in items {
            let name_str = account.name.as_deref();

            let res = validate_one_strong(
                &self.token_issuer,
                self.user_ip,
                account.account_id,
                account.user_id,
                name_str,
                &account.token,
            );

            response.items.push(WithId {
                id: account.account_id,
                value: res,
            });
        }

        Ok(ServerMessage::ValidateStrongResponse(response))
    }

    async fn validate_check_data(&mut self, items: &[UserAuthData]) -> Result<ServerMessage, HandleError> {
        if let Err(e) = self.validate_req(items.len()).await {
            return Err(HandleError::Other(e));
        }

        // finally, validate the tokens
        let mut response = ValidateCheckDataManyResponseMessage {
            items: Vec::with_capacity(items.len()),
        };

        for account in items {
            let res = validate_one_check(
                &self.token_issuer,
                self.user_ip,
                account.account_id,
                &account.token,
            );

            response.items.push(WithId {
                id: account.account_id,
                value: res,
            });
        }

        Ok(ServerMessage::ValidateCheckDataManyResponse(response))
    }

    async fn validate_req(&mut self, items: usize) -> Result<(), String> {
        if items > MAX_USERS_IN_REQUEST {
            debug!(
                "[{}] tried validating {} tokens, rejecting due to rate limit",
                self.user_ip, items
            );

            return Err(format!(
                "Too many users in request: {items}/{MAX_USERS_IN_REQUEST}"
            ));
        }

        let mut db = None;
        let res = self
            .token_manager
            .validate_tokens_session(
                self.token_id.unwrap(),
                async || match self.db_pool.get_one().await {
                    Ok(x) => {
                        db = Some(x);
                        Ok(db.as_ref().unwrap())
                    }

                    Err(err) => {
                        warn!("[{}] failed to get database connection: {}", self.user_ip, err);
                        Err("failed to get database connection")
                    }
                },
                items,
            )
            .await;

        match res {
            Ok(true) => {}
            Ok(false) => {
                return Err("Rate limit exceeded".to_string());
            }

            Err(TokenFetchError::DatabasePoolError) => {
                return Err(
                    "server error, please try again later (failed to get database connection)".to_string(),
                );
            }

            Err(e) => {
                warn!(
                    "[{}] Failed to validate tokens (token fetch failed): {e}",
                    self.user_ip
                );
                return Err(format!("server error, please try again later ({e})"));
            }
        };

        Ok(())
    }
}

#[get("/ws")]
pub fn ws_handler(
    ws: ws::WebSocket,
    ip: CloudflareIPGuard,
    token_manager: &State<Arc<ApiTokenManager>>,
    token_issuer: &State<Arc<TokenIssuer>>,
    health_state: &State<Arc<ServerHealthState>>,
    db_pool: &State<Arc<ArgonDbPool>>,
) -> ws::Channel<'static> {
    let user_ip = ip.0;
    let token_manager = token_manager.inner().clone();
    let health_state = health_state.inner().clone();
    let token_issuer = token_issuer.inner().clone();
    let db_pool = db_pool.inner().clone();

    ws.channel(move |stream| {
        Box::pin(async move {
            let mut conn = ClientConnection {
                protocol: WsProtocol::Json,
                token_id: None,
                token_manager,
                health_state,
                token_issuer,
                db_pool,
                user_ip,
                stream,
                closed: false,
            };

            if let Err(e) = conn.run_loop().await {
                error!("WebSocket connection error (from {user_ip}): {:?}", e);
            }

            Ok(())
        })
    })
}

fn encode_message(msg: &ServerMessage, mut protocol: WsProtocol) -> Result<ws::Message, HandleError> {
    // authack is always json
    if matches!(msg, ServerMessage::AuthAck) {
        protocol = WsProtocol::Json;
    }

    match protocol {
        WsProtocol::Binary => Ok(ws::Message::Binary(encode_message_binary(msg)?)),

        WsProtocol::Json => Ok(ws::Message::Text(encode_message_json(msg)?)),

        WsProtocol::JsonZstd => {
            let val = encode_message_json(msg)?;

            let json_str = serde_json::to_string(&val).map_err(HandleError::Serialization)?;
            let mut out_vec = Vec::new();

            zstd::stream::copy_encode(Cursor::new(json_str), &mut out_vec, 0)
                .map_err(HandleError::Compression)?;

            Ok(ws::Message::Binary(out_vec))
        }
    }
}

fn encode_message_binary(msg: &ServerMessage) -> Result<Vec<u8>, HandleError> {
    let mut bytes = BytesMut::with_capacity(128);
    bytes.put_u8(msg.numeric_id());
    msg.encode_binary(&mut bytes);

    Ok(bytes.to_vec())
}

fn encode_message_json(msg: &ServerMessage) -> Result<String, HandleError> {
    let json = serde_json::json!({
        "type": msg.type_name(),
        "data": msg.encode_json()?
    });

    Ok(json.to_string())
}

fn encode_fatal_error(s: &str, protocol: WsProtocol) -> Result<ws::Message, HandleError> {
    encode_message(&ServerMessage::FatalError(s.to_owned()), protocol)
}

fn encode_error(s: &str, protocol: WsProtocol) -> Result<ws::Message, HandleError> {
    encode_message(&ServerMessage::Error(s.to_owned()), protocol)
}

fn decode_message(msg: &ws::Message, protocol: WsProtocol) -> Result<ClientMessage, HandleError> {
    match protocol {
        WsProtocol::Json => decode_message_json(
            msg.to_text()
                .map_err(|_| HandleError::InvalidRequest("expected text message for json protocol"))?,
        ),
        WsProtocol::JsonZstd => {
            let ws::Message::Binary(bytes) = msg else {
                return Err(HandleError::InvalidRequest(
                    "expected binary message for json-zstd protocol",
                ));
            };

            let mut out_vec = Vec::new();
            zstd::stream::copy_decode(Cursor::new(bytes), &mut out_vec).map_err(HandleError::Compression)?;

            let text = String::from_utf8(out_vec)
                .map_err(|_| HandleError::InvalidRequest("invalid utf-8 in json-zstd message"))?;

            decode_message_json(&text)
        }
        WsProtocol::Binary => decode_message_binary(msg),
    }
}

fn decode_message_json(msg: &str) -> Result<ClientMessage, HandleError> {
    let value: Value = serde_json::from_str(msg)?;
    ClientMessage::decode_json(&value)
}

fn decode_message_binary(msg: &ws::Message) -> Result<ClientMessage, HandleError> {
    let ws::Message::Binary(bytes) = msg else {
        return Err(HandleError::InvalidRequest(
            "expected binary message for json-zstd protocol",
        ));
    };

    ClientMessage::decode_binary(bytes)
}
