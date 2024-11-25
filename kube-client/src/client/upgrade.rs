use std::str::FromStr;

use http::{self, Response, StatusCode};
use thiserror::Error;
use tokio_tungstenite::{tungstenite as ws, WebSocketStream};

use crate::client::Body;

// Binary subprotocol v4. implements v3 and adds support for json exit codes.
pub const WS_PROTOCOL_V4: &str = "v4.channel.k8s.io";

// Binary subprotocol v5. implements v4 and adds CLOSE signal.
pub const WS_PROTOCOL_V5: &str = "v5.channel.k8s.io";

pub const WS_PROTOCOLS: &str = "v5.channel.k8s.io,v4.channel.k8s.io";

#[cfg(feature = "ws")]
#[derive(Debug, Clone, Copy)]
pub enum SubProto {
    V4,
    V5,
}

impl FromStr for SubProto {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            WS_PROTOCOL_V4 => Ok(SubProto::V4),
            WS_PROTOCOL_V5 => Ok(SubProto::V5),
            _ => Err("invalid subprotocol"),
        }
    }
}
#[allow(missing_docs)]
#[cfg(feature = "ws")]
#[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
pub struct WsStream<S> {
    stream: WebSocketStream<S>,
    proto: SubProto,
}

impl<S> WsStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Sized + Send + 'static,
{
    #[allow(missing_docs)]
    pub fn new(stream: WebSocketStream<S>, proto: SubProto) -> Self {
        Self { stream, proto }
    }
    #[allow(missing_docs)]
    pub fn into_inner(self) -> WebSocketStream<S> {
        self.stream
    }
    #[allow(missing_docs)]
    pub fn supports_closing(&self) -> bool {
        matches!(self.proto, SubProto::V5)
    }
}

/// Possible errors from upgrading to a WebSocket connection
#[cfg(feature = "ws")]
#[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
#[derive(Debug, Error)]
pub enum UpgradeConnectionError {
    /// The server did not respond with [`SWITCHING_PROTOCOLS`] status when upgrading the
    /// connection.
    ///
    /// [`SWITCHING_PROTOCOLS`]: http::status::StatusCode::SWITCHING_PROTOCOLS
    #[error("failed to switch protocol: {0}")]
    ProtocolSwitch(http::status::StatusCode),

    /// `Upgrade` header was not set to `websocket` (case insensitive)
    #[error("upgrade header was not set to websocket")]
    MissingUpgradeWebSocketHeader,

    /// `Connection` header was not set to `Upgrade` (case insensitive)
    #[error("connection header was not set to Upgrade")]
    MissingConnectionUpgradeHeader,

    /// `Sec-WebSocket-Accept` key mismatched.
    #[error("Sec-WebSocket-Accept key mismatched")]
    SecWebSocketAcceptKeyMismatch,

    /// `Sec-WebSocket-Protocol` mismatched.
    #[error("Sec-WebSocket-Protocol mismatched")]
    SecWebSocketProtocolMismatch,

    /// Failed to get pending HTTP upgrade.
    #[error("failed to get pending HTTP upgrade: {0}")]
    GetPendingUpgrade(#[source] hyper::Error),
}

// Verify upgrade response according to RFC6455.
// Based on `tungstenite` and added subprotocol verification.
pub fn verify_response(res: &Response<Body>, key: &str) -> Result<SubProto, UpgradeConnectionError> {
    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(UpgradeConnectionError::ProtocolSwitch(res.status()));
    }

    let headers = res.headers();
    if !headers
        .get(http::header::UPGRADE)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
    {
        return Err(UpgradeConnectionError::MissingUpgradeWebSocketHeader);
    }

    if !headers
        .get(http::header::CONNECTION)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.eq_ignore_ascii_case("Upgrade"))
        .unwrap_or(false)
    {
        return Err(UpgradeConnectionError::MissingConnectionUpgradeHeader);
    }

    let accept_key = ws::handshake::derive_accept_key(key.as_ref());
    if !headers
        .get(http::header::SEC_WEBSOCKET_ACCEPT)
        .map(|h| h == &accept_key)
        .unwrap_or(false)
    {
        return Err(UpgradeConnectionError::SecWebSocketAcceptKeyMismatch);
    }
    // Check for supported subprotocol and return it
    headers
        .get(http::header::SEC_WEBSOCKET_PROTOCOL)
        .map(|h| {
            SubProto::from_str(h.to_str().unwrap_or(""))
                .map_err(|_| UpgradeConnectionError::SecWebSocketProtocolMismatch)
        })
        .take()
        .unwrap_or(Err(UpgradeConnectionError::SecWebSocketProtocolMismatch))
}

/// Generate a random key for the `Sec-WebSocket-Key` header.
/// This must be nonce consisting of a randomly selected 16-byte value in base64.
pub fn sec_websocket_key() -> String {
    use base64::Engine;
    let r: [u8; 16] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(r)
}
