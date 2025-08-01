use std::{fmt::Write, io::Cursor, net::IpAddr, sync::Arc};

use argon_shared::logger::*;
use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};
use rocket::{State, get};
use serde::{Deserialize, Serialize};
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
use rocket_ws as ws;

#[derive(Debug, Error)]
enum WsHandleError {
    #[error("Cannot perform this action while unauthorized")]
    Unauthorized,
    #[error("Invalid API token provided, please read the WebSockets section in the server documentation")]
    InvalidAuth,
    #[error("Other message than Auth was sent as the first message")]
    ExpectedAuth,
    #[error("Invalid or malformed request received: {0}")]
    InvalidRequest(&'static str),
    #[error("Failed to serialize response: {0}")]
    Serialization(serde_json::Error),
    #[error("Failed to deserialize response: {0}")]
    Deserialization(serde_json::Error),
    #[error("Failed to compress response: {0}")]
    Compression(std::io::Error),
    // #[error("Websocket error: {0}")]
    // Websocket(#[from] ws::result::Error),
}

impl From<TryGetError> for WsHandleError {
    fn from(_: TryGetError) -> Self {
        Self::InvalidRequest("malformed binary message, could not properly decode data")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WsMessageAuth {
    token: String,
    proto: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WsMessageError {
    error: String,
}

#[derive(Deserialize, Debug, Clone)]
struct WsMessageValidate {
    items: Vec<UserAuthData>,
}

#[derive(Serialize, Debug, Clone)]
struct WsMessageValidateResponse {
    items: Vec<WithId<ValidationResponse>>,
}

#[derive(Deserialize, Debug, Clone)]
struct WsMessageValidateStrong {
    items: Vec<StrongUserAuthData>,
}

#[derive(Serialize, Debug, Clone)]
struct WsMessageValidateStrongResponse {
    items: Vec<WithId<StrongValidationResponse>>,
}

#[derive(Deserialize, Debug, Clone)]
struct WsMessageValidateCheckDataMany {
    items: Vec<UserAuthData>,
}

#[derive(Serialize, Debug, Clone)]
struct WsMessageValidateCheckDataManyResponse {
    items: Vec<WithId<UserCheckResponse>>,
}

enum WsMessageData {
    Auth(WsMessageAuth),
    AuthAck,
    FatalError(WsMessageError),
    Error(WsMessageError),
    Status,
    StatusResponse(ServerStatusResponse),
    Validate(WsMessageValidate),
    ValidateResponse(WsMessageValidateResponse),
    ValidateStrong(WsMessageValidateStrong),
    ValidateStrongResponse(WsMessageValidateStrongResponse),
    ValidateCheckDataMany(WsMessageValidateCheckDataMany),
    ValidateCheckDataManyResponse(WsMessageValidateCheckDataManyResponse),
}

impl WsMessageData {
    fn type_name(&self) -> &'static str {
        match self {
            WsMessageData::Auth(_) => "Auth",
            WsMessageData::AuthAck => "AuthAck",
            WsMessageData::FatalError(_) => "FatalError",
            WsMessageData::Error(_) => "Error",
            WsMessageData::Status => "Status",
            WsMessageData::StatusResponse(_) => "StatusResponse",
            WsMessageData::Validate(_) => "Validate",
            WsMessageData::ValidateResponse(_) => "ValidateResponse",
            WsMessageData::ValidateStrong(_) => "ValidateStrong",
            WsMessageData::ValidateStrongResponse(_) => "ValidateStrongResponse",
            WsMessageData::ValidateCheckDataMany(_) => "ValidateCheckDataMany",
            WsMessageData::ValidateCheckDataManyResponse(_) => "ValidateCheckDataManyResponse",
        }
    }

    fn numeric_id(&self) -> u8 {
        match self {
            Self::Auth(_) => 1,
            Self::AuthAck => 2,
            Self::FatalError(_) => 3,
            Self::Error(_) => 4,
            Self::Status => 5,
            Self::StatusResponse(_) => 6,
            Self::Validate(_) => 7,
            Self::ValidateResponse(_) => 8,
            Self::ValidateStrong(_) => 9,
            Self::ValidateStrongResponse(_) => 10,
            Self::ValidateCheckDataMany(_) => 13,
            Self::ValidateCheckDataManyResponse(_) => 14,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum WsProtocol {
    Json,
    JsonZstd,
    Binary,
}

struct WsState {
    protocol: WsProtocol,
    token_id: Option<i32>,
    token_manager: Arc<ApiTokenManager>,
    health_state: Arc<ServerHealthState>,
    token_issuer: Arc<TokenIssuer>,
    db_pool: Arc<ArgonDbPool>,
    user_ip: IpAddr,
}

impl WsState {
    pub fn new(
        token_manager: Arc<ApiTokenManager>,
        health_state: Arc<ServerHealthState>,
        token_issuer: Arc<TokenIssuer>,
        db_pool: Arc<ArgonDbPool>,
        user_ip: IpAddr,
    ) -> Self {
        Self {
            protocol: WsProtocol::Json,
            token_id: None,
            token_manager,
            health_state,
            token_issuer,
            db_pool,
            user_ip,
        }
    }

    fn encode_message_json(&self, data: &WsMessageData) -> Result<serde_json::Value, WsHandleError> {
        let data_val = match data {
            // these types are never encoded by the server
            WsMessageData::Auth(_)
            | WsMessageData::Status
            | WsMessageData::Validate(_)
            | WsMessageData::ValidateStrong(_)
            | WsMessageData::ValidateCheckDataMany(_) => {
                unreachable!("this message type should never be encoded by the server")
            }

            WsMessageData::AuthAck => serde_json::Value::Null,
            WsMessageData::Error(e) | WsMessageData::FatalError(e) => {
                serde_json::json!({ "error": e.error })
            }
            WsMessageData::StatusResponse(r) => {
                serde_json::to_value(r).map_err(WsHandleError::Serialization)?
            }
            WsMessageData::ValidateResponse(r) => {
                serde_json::to_value(&r.items).map_err(WsHandleError::Serialization)?
            }
            WsMessageData::ValidateStrongResponse(r) => {
                serde_json::to_value(&r.items).map_err(WsHandleError::Serialization)?
            }
            WsMessageData::ValidateCheckDataManyResponse(r) => {
                serde_json::to_value(&r.items).map_err(WsHandleError::Serialization)?
            }
        };

        Ok(serde_json::json!({
            "type": data.type_name(),
            "data": data_val,
        }))
    }

    fn encode_message_binary(&self, data: &WsMessageData) -> Result<Vec<u8>, WsHandleError> {
        let mut bytes = BytesMut::with_capacity(128);
        bytes.put_u8(data.numeric_id());

        let write_str = |bytes: &mut BytesMut, s: &str| -> () {
            bytes.put_u16((s.len() as u16).to_be());
            let _ = bytes.write_str(s);
        };

        match data {
            WsMessageData::Auth(_)
            | WsMessageData::Status
            | WsMessageData::Validate(_)
            | WsMessageData::ValidateStrong(_)
            | WsMessageData::ValidateCheckDataMany(_) => {
                unreachable!("this message type should never be encoded by the server")
            }

            WsMessageData::AuthAck => {}
            WsMessageData::Error(e) | WsMessageData::FatalError(e) => {
                write_str(&mut bytes, &e.error);
            }
            WsMessageData::StatusResponse(r) => {
                bytes.put_u8(r.active as u8);
                bytes.put_i32((r.total_nodes as i32).to_be());
                bytes.put_i32((r.active_nodes as i32).to_be());
                write_str(&mut bytes, &r.ident);
            }
            WsMessageData::ValidateResponse(r) => {
                bytes.put_u16((r.items.len() as u16).to_be());
                for item in &r.items {
                    bytes.put_i32(item.id.to_be());
                    bytes.put_u8(item.value.valid as u8);

                    if let Some(cause) = &item.value.cause {
                        write_str(&mut bytes, cause);
                    }
                }
            }
            WsMessageData::ValidateStrongResponse(r) => {
                bytes.put_u16((r.items.len() as u16).to_be());
                for item in &r.items {
                    bytes.put_i32(item.id.to_be());
                    bytes.put_u8(item.value.valid as u8);
                    bytes.put_u8(item.value.valid_weak as u8);

                    if let Some(cause) = &item.value.cause {
                        assert!(!item.value.valid);
                        write_str(&mut bytes, cause);
                    }

                    if let Some(username) = &item.value.username {
                        assert!(item.value.valid);
                        write_str(&mut bytes, username);
                    }
                }
            }
            WsMessageData::ValidateCheckDataManyResponse(r) => {
                bytes.put_u16((r.items.len() as u16).to_be());
                for item in &r.items {
                    bytes.put_i32(item.id.to_be());
                    bytes.put_u8(item.value.valid as u8);

                    if let Some(cause) = &item.value.cause {
                        assert!(!item.value.valid);
                        write_str(&mut bytes, cause);
                    } else {
                        assert!(item.value.valid);
                        let user_id = item.value.user_id.unwrap_or(0);
                        bytes.put_i32(user_id.to_be());
                        write_str(&mut bytes, item.value.username.as_deref().unwrap_or(""));
                    }
                }
            }
        };

        Ok(bytes.to_vec())
    }

    fn encode_message_with(
        &self,
        data: &WsMessageData,
        protocol: WsProtocol,
    ) -> Result<ws::Message, WsHandleError> {
        match protocol {
            WsProtocol::Json => {
                let val = self.encode_message_json(data)?;
                Ok(ws::Message::Text(
                    serde_json::to_string(&val).map_err(WsHandleError::Serialization)?,
                ))
            }

            WsProtocol::JsonZstd => {
                let val = self.encode_message_json(data)?;

                let json_str = serde_json::to_string(&val).map_err(WsHandleError::Serialization)?;
                let mut out_vec = Vec::new();

                zstd::stream::copy_encode(Cursor::new(json_str), &mut out_vec, 0)
                    .map_err(WsHandleError::Compression)?;

                Ok(ws::Message::Binary(out_vec))
            }

            WsProtocol::Binary => {
                let bin_data = self.encode_message_binary(data)?;
                Ok(ws::Message::Binary(bin_data))
            }
        }
    }

    fn encode_message(&self, data: &WsMessageData) -> Result<ws::Message, WsHandleError> {
        self.encode_message_with(data, self.protocol)
    }

    fn decode_message_json(&self, data: &serde_json::Value) -> Result<WsMessageData, WsHandleError> {
        let r#type = data["type"]
            .as_str()
            .ok_or(WsHandleError::InvalidRequest("missing or invalid type"))?;

        match r#type {
            "Auth" => {
                let auth_data: WsMessageAuth =
                    serde_json::from_value(data["data"].clone()).map_err(WsHandleError::Deserialization)?;
                Ok(WsMessageData::Auth(auth_data))
            }

            "Status" => Ok(WsMessageData::Status),

            "Validate" => {
                let items: Vec<UserAuthData> =
                    serde_json::from_value(data["data"].clone()).map_err(WsHandleError::Deserialization)?;
                Ok(WsMessageData::Validate(WsMessageValidate { items }))
            }

            "ValidateStrong" => {
                let items: Vec<StrongUserAuthData> =
                    serde_json::from_value(data["data"].clone()).map_err(WsHandleError::Deserialization)?;
                Ok(WsMessageData::ValidateStrong(WsMessageValidateStrong { items }))
            }

            "ValidateCheckDataMany" => {
                let items: Vec<UserAuthData> =
                    serde_json::from_value(data["data"].clone()).map_err(WsHandleError::Deserialization)?;
                Ok(WsMessageData::ValidateCheckDataMany(
                    WsMessageValidateCheckDataMany { items },
                ))
            }

            _ => Err(WsHandleError::InvalidRequest("unknown client-side message type")),
        }
    }

    fn decode_message_binary(&self, data: Vec<u8>) -> Result<WsMessageData, WsHandleError> {
        let mut bytes = Bytes::from(data);
        let msg_type = bytes.try_get_u8()?;

        let read_str = |bytes: &mut Bytes| -> Result<String, WsHandleError> {
            let len = bytes.try_get_u16()?.to_be() as usize;
            if bytes.remaining() < len {
                return Err(WsHandleError::InvalidRequest(
                    "invalid string length in binary message",
                ));
            }

            let str_data = bytes.copy_to_bytes(len);
            Ok(String::from_utf8_lossy(str_data.as_ref()).to_string())
        };

        fn read_vec<T, F: Fn(&mut Bytes) -> Result<T, WsHandleError>>(
            bytes: &mut Bytes,
            decode_fn: F,
        ) -> Result<Vec<T>, WsHandleError> {
            let length = bytes.try_get_u16()?.to_be() as usize;
            let mut output = Vec::new();

            for _ in 0..length {
                output.push(decode_fn(bytes)?);
            }

            Ok(output)
        }

        match msg_type {
            // 1 = Auth
            1 => {
                let token = read_str(&mut bytes)?;
                let proto = read_str(&mut bytes)?;

                Ok(WsMessageData::Auth(WsMessageAuth {
                    token: token.to_string(),
                    proto: proto.to_string(),
                }))
            }

            // 5 = Status
            5 => Ok(WsMessageData::Status),

            // 7 = Validate
            7 => {
                let elems = read_vec(&mut bytes, |b| {
                    let account_id = b.try_get_i32()?.to_be();
                    let token = read_str(b)?;

                    Ok(UserAuthData {
                        account_id,
                        token: token.to_string(),
                    })
                })?;

                Ok(WsMessageData::Validate(WsMessageValidate { items: elems }))
            }

            // 9 = ValidateStrong
            9 => {
                let elems = read_vec(&mut bytes, |b| {
                    let account_id = b.try_get_i32()?.to_be();
                    let user_id = if b.try_get_u8()? != 0 {
                        Some(b.try_get_i32()?.to_be())
                    } else {
                        None
                    };

                    let user_name = if b.try_get_u8()? != 0 {
                        Some(read_str(b)?.to_string())
                    } else {
                        None
                    };

                    let token = read_str(b)?;

                    Ok(StrongUserAuthData {
                        account_id,
                        token: token.to_string(),
                        name: user_name,
                        user_id,
                    })
                })?;

                Ok(WsMessageData::ValidateStrong(WsMessageValidateStrong {
                    items: elems,
                }))
            }

            // 13 = ValidateCheckDataMany
            13 => {
                let elems = read_vec(&mut bytes, |b| {
                    let account_id = b.try_get_i32()?.to_be();
                    let token = read_str(b)?;

                    Ok(UserAuthData {
                        account_id,
                        token: token.to_string(),
                    })
                })?;

                Ok(WsMessageData::ValidateCheckDataMany(
                    WsMessageValidateCheckDataMany { items: elems },
                ))
            }

            _ => Err(WsHandleError::InvalidRequest("unknown message type")),
        }
    }

    fn decode_message_with(
        &self,
        data: ws::Message,
        protocol: WsProtocol,
    ) -> Result<WsMessageData, WsHandleError> {
        match protocol {
            WsProtocol::Json => {
                let text = match data {
                    ws::Message::Text(text) => text,
                    _ => {
                        return Err(WsHandleError::InvalidRequest(
                            "expected text message when using json protocol",
                        ));
                    }
                };

                self.decode_message_json(
                    &serde_json::from_str::<serde_json::Value>(&text)
                        .map_err(WsHandleError::Deserialization)?,
                )
            }

            WsProtocol::JsonZstd => {
                let bin_data = match data {
                    ws::Message::Binary(bin) => bin,
                    _ => {
                        return Err(WsHandleError::InvalidRequest(
                            "expected binary message when using json-zstd protocol",
                        ));
                    }
                };

                let mut out_vec = Vec::new();
                zstd::stream::copy_decode(Cursor::new(bin_data), &mut out_vec)
                    .map_err(WsHandleError::Compression)?;

                let text = String::from_utf8(out_vec)
                    .map_err(|_| WsHandleError::InvalidRequest("invalid utf-8 in json-zstd message"))?;

                self.decode_message_json(
                    &serde_json::from_str::<serde_json::Value>(&text)
                        .map_err(WsHandleError::Deserialization)?,
                )
            }

            WsProtocol::Binary => {
                let bin_data = match data {
                    ws::Message::Binary(bin) => bin,
                    _ => {
                        return Err(WsHandleError::InvalidRequest(
                            "expected binary message when using json-zstd protocol",
                        ));
                    }
                };

                self.decode_message_binary(bin_data)
            }
        }
    }

    fn decode_message(&self, msg: ws::Message) -> Result<WsMessageData, WsHandleError> {
        self.decode_message_with(msg, self.protocol)
    }

    fn error(&self, msg: String, fatal: bool) -> Result<ws::Message, WsHandleError> {
        self.encode_message(&if fatal {
            WsMessageData::FatalError(WsMessageError { error: msg })
        } else {
            WsMessageData::Error(WsMessageError { error: msg })
        })
    }

    async fn handle_ws_message(&mut self, msg: ws::Message) -> Result<ws::Message, WsHandleError> {
        // if unauthorized, first message must be an authentication request
        if self.token_id.is_none() {
            self.try_authenticate(&msg)?;
            return self.encode_message_with(&WsMessageData::AuthAck, WsProtocol::Json);
        }

        let msg = self.decode_message(msg)?;

        match msg {
            WsMessageData::Status => {
                self.encode_message(&WsMessageData::StatusResponse(self.health_state.status()))
            }

            WsMessageData::Validate(WsMessageValidate { items }) => self.validate_weak(&items).await,

            WsMessageData::ValidateStrong(WsMessageValidateStrong { items }) => {
                self.validate_strong(&items).await
            }

            WsMessageData::ValidateCheckDataMany(WsMessageValidateCheckDataMany { items }) => {
                self.validate_check_data(&items).await
            }

            WsMessageData::Auth(_) => self.error("Already authenticated".to_string(), false),
            WsMessageData::AuthAck
            | WsMessageData::StatusResponse(_)
            | WsMessageData::ValidateResponse(_)
            | WsMessageData::ValidateStrongResponse(_)
            | WsMessageData::ValidateCheckDataManyResponse(_)
            | WsMessageData::Error(_)
            | WsMessageData::FatalError(_) => {
                // these messages are not expected to be sent by the client
                self.error("Unexpected message received".to_string(), false)
            }
        }
    }

    fn try_authenticate(&mut self, msg: &ws::Message) -> Result<(), WsHandleError> {
        let json_data = match msg {
            ws::Message::Text(x) => x,
            _ => {
                debug!("[{}] Websocket client sent a non-text auth message", self.user_ip);
                return Err(WsHandleError::ExpectedAuth);
            }
        };

        let val: serde_json::Value = json_data.parse().map_err(WsHandleError::Deserialization)?;
        if val["type"].as_str().unwrap_or_default() != "Auth" {
            return Err(WsHandleError::ExpectedAuth);
        }

        let auth_data: WsMessageAuth =
            serde_json::from_value(val["data"].clone()).map_err(WsHandleError::Deserialization)?;

        self.token_id = Some(
            self.token_manager
                .validate_api_token(&auth_data.token)
                .map_err(|err| {
                    warn!("[{}] Failed to validate API token: {err}", self.user_ip);
                    WsHandleError::InvalidAuth
                })?,
        );

        self.protocol = match auth_data.proto.as_str() {
            "json" => WsProtocol::Json,
            "json-zstd" => WsProtocol::JsonZstd,
            "binary-v1" => WsProtocol::Binary,
            _ => {
                debug!(
                    "[{}] Websocket client sent an unsupported protocol: {}",
                    self.user_ip, auth_data.proto
                );

                return Err(WsHandleError::InvalidRequest(
                    "Unsupported protocol, must be one of: json, json-zstd, binary-v1",
                ));
            }
        };

        Ok(())
    }

    async fn validate_weak(&self, items: &[UserAuthData]) -> Result<ws::Message, WsHandleError> {
        if let Err(msg) = self.validate_req(items.len()).await {
            return msg;
        }

        // finally, validate the tokens
        let mut response = WsMessageValidateResponse {
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

        let response = WsMessageData::ValidateResponse(response);
        self.encode_message(&response)
    }

    async fn validate_strong(&self, items: &[StrongUserAuthData]) -> Result<ws::Message, WsHandleError> {
        if let Err(msg) = self.validate_req(items.len()).await {
            return msg;
        }

        // finally, validate the tokens
        let mut response = WsMessageValidateStrongResponse {
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

        let response = WsMessageData::ValidateStrongResponse(response);
        self.encode_message(&response)
    }

    async fn validate_check_data(&self, items: &[UserAuthData]) -> Result<ws::Message, WsHandleError> {
        if let Err(msg) = self.validate_req(items.len()).await {
            return msg;
        }

        // finally, validate the tokens
        let mut response = WsMessageValidateCheckDataManyResponse {
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

        let response = WsMessageData::ValidateCheckDataManyResponse(response);
        self.encode_message(&response)
    }

    async fn validate_req(&self, items: usize) -> Result<(), Result<ws::Message, WsHandleError>> {
        if items > MAX_USERS_IN_REQUEST {
            debug!(
                "[{}] tried validating {} tokens, rejecting due to rate limit",
                self.user_ip, items
            );

            return Err(self.error(
                format!("Too many users in request: {items}/{MAX_USERS_IN_REQUEST}"),
                false,
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
                return Err(self.error("Rate limit exceeded".to_string(), false));
            }

            Err(TokenFetchError::DatabasePoolError) => {
                return Err(self.error(
                    "server error, please try again later (failed to get database connection)".to_string(),
                    false,
                ));
            }

            Err(e) => {
                warn!(
                    "[{}] Failed to validate tokens (token fetch failed): {e}",
                    self.user_ip
                );
                return Err(self.error(format!("server error, please try again later ({e})"), false));
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
    use rocket::futures::{SinkExt, StreamExt};

    let user_ip = ip.0;
    let token_manager = token_manager.inner().clone();
    let health_state = health_state.inner().clone();
    let token_issuer = token_issuer.inner().clone();
    let db_pool = db_pool.inner().clone();

    ws.channel(move |mut stream| {
        Box::pin(async move {
            let mut state = WsState::new(token_manager, health_state, token_issuer, db_pool, user_ip);

            while let Some(message) = stream.next().await {
                let res = state.handle_ws_message(message?).await;

                let message = match res {
                    Ok(x) => Ok(x),

                    Err(err @ WsHandleError::Unauthorized) | Err(err @ WsHandleError::InvalidAuth) => {
                        // fatal error
                        state.error(err.to_string(), true)
                    }

                    Err(err) => {
                        warn!("[{user_ip}] Error handling websocket message: {err}");
                        state.error(err.to_string(), false)
                    }
                };

                let message = match message {
                    Ok(x) => x,
                    Err(e) => {
                        warn!("[{user_ip}] failed to encode websocket error message: {e}");
                        break;
                    }
                };

                if let Err(e) = stream.send(message).await {
                    warn!("[{user_ip}] Failed to send websocket message, terminating: {e}");
                    break;
                }
            }

            Ok(())
        })
    })
}
