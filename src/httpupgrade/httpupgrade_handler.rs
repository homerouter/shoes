use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;

use crate::address::ResolvedLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::prepend_stream::PrependStream;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    ClientTransport, TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

pub const MAX_LINE: usize = 4096;
pub const MAX_HTTP: usize = 16384;
pub const MAX_HTTP_LINES: usize = 64;

pub(crate) fn validate_client_config(
    path: Option<&str>,
    headers: Option<&HashMap<String, String>>,
) -> io::Result<()> {
    validate_path(path)?;
    validate_headers(headers, false)?;
    Ok(())
}

pub(crate) fn validate_server_config(
    path: Option<&str>,
    headers: Option<&HashMap<String, String>>,
) -> io::Result<()> {
    validate_path(path)?;
    validate_headers(headers, true)?;
    Ok(())
}

fn validate_path(path: Option<&str>) -> io::Result<()> {
    if let Some(path) = path {
        if !path.starts_with('/')
            || !path.is_ascii()
            || path.bytes().any(|b| b.is_ascii_control() || b == b' ')
            || path.contains('#')
            || path.len() >= MAX_LINE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid HTTPUpgrade matching_path",
            ));
        }
    }
    Ok(())
}

fn validate_headers(headers: Option<&HashMap<String, String>>, is_server: bool) -> io::Result<()> {
    if let Some(headers) = headers {
        for (name, value) in headers {
            let header_name = http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid HTTP header name"))?;
            http::HeaderValue::from_str(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid HTTP header value"))?;
            let lower = header_name.as_str().to_ascii_lowercase();
            if !is_server && matches!(lower.as_str(), "upgrade" | "connection") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "matching_headers conflicts with HTTPUpgrade handshake headers",
                ));
            }
        }
    }
    Ok(())
}

fn has_token(headers: &HashMap<String, String>, name: &str, token: &str) -> bool {
    headers.get(name).is_some_and(|value| {
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

async fn reject_upgrade(stream: &mut Box<dyn AsyncStream>, status: &str) -> io::Error {
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    if let Err(error) = stream.write_all(response.as_bytes()).await {
        return error;
    }
    if let Err(error) = stream.flush().await {
        return error;
    }
    io::Error::new(io::ErrorKind::InvalidData, status.to_owned())
}

struct ParsedHttpData {
    first_line: String,
    headers: HashMap<String, String>,
    stream_reader: StreamReader,
}

impl ParsedHttpData {
    async fn parse(stream: &mut Box<dyn AsyncStream>) -> io::Result<Self> {
        let mut stream_reader = StreamReader::new();
        let mut first_line: Option<String> = None;
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut total = 0;
        let mut line_count = 0;

        loop {
            let line = stream_reader.read_line(stream).await?;
            total += line.len() + 2;
            if total > MAX_HTTP {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP header block is too long",
                ));
            }
            if line.is_empty() {
                break;
            }
            if line.len() >= MAX_LINE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP line is too long",
                ));
            }
            if first_line.is_none() {
                first_line = Some(line.to_string());
            } else {
                let (name, value) = line.split_once(':').ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP header line")
                })?;
                let header_key = name.trim().to_lowercase();
                let header_value = value.trim().to_string();
                if let Some(previous) = headers.get_mut(&header_key) {
                    previous.push_str(", ");
                    previous.push_str(&header_value);
                } else {
                    headers.insert(header_key, header_value);
                }
            }
            line_count += 1;
            if line_count >= MAX_HTTP_LINES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP header count exceeded limit",
                ));
            }
        }

        let first_line = first_line.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "empty HTTP request")
        })?;

        Ok(Self {
            first_line,
            headers,
            stream_reader,
        })
    }
}

#[derive(Debug)]
pub struct HttpUpgradeTcpClientHandler {
    authority: String,
    matching_path: Option<String>,
    matching_headers: Option<FxHashMap<String, String>>,
    handler: Box<dyn TcpClientHandler>,
}

impl HttpUpgradeTcpClientHandler {
    pub fn new(
        authority: String,
        matching_path: Option<String>,
        matching_headers: Option<FxHashMap<String, String>>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        let matching_path = matching_path.map(|p| {
            if p.starts_with('/') {
                p
            } else {
                format!("/{p}")
            }
        });
        Self {
            authority,
            matching_path,
            matching_headers,
            handler,
        }
    }

    async fn setup_client_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let request_path = self.matching_path.as_deref().unwrap_or("/");
        let mut request = String::with_capacity(512);
        request.push_str("GET ");
        request.push_str(request_path);
        request.push_str(" HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n");

        if !self
            .matching_headers
            .as_ref()
            .is_some_and(|headers| headers.keys().any(|key| key.eq_ignore_ascii_case("host")))
        {
            request.push_str("Host: ");
            request.push_str(&self.authority);
            request.push_str("\r\n");
        }

        if let Some(ref headers) = self.matching_headers {
            for (key, val) in headers {
                request.push_str(key);
                request.push_str(": ");
                request.push_str(val);
                request.push_str("\r\n");
            }
        }
        request.push_str("\r\n");

        client_stream.write_all(request.as_bytes()).await?;
        client_stream.flush().await?;

        let ParsedHttpData {
            first_line,
            headers,
            stream_reader,
        } = ParsedHttpData::parse(&mut client_stream).await?;

        let mut status = first_line.split_whitespace();
        if !matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")) || status.next() != Some("101") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad HTTP upgrade status: {first_line}"),
            ));
        }
        if !has_token(&headers, "upgrade", "websocket") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing or invalid Upgrade header in HTTP upgrade response",
            ));
        }
        if !has_token(&headers, "connection", "upgrade") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing or invalid Connection header in HTTP upgrade response",
            ));
        }

        let unparsed = stream_reader.unparsed_data_owned();
        let stream: Box<dyn AsyncStream> = match unparsed {
            Some(data) => Box::new(PrependStream::new(client_stream, Some(data))),
            None => client_stream,
        };
        Ok(stream)
    }
}

#[async_trait]
impl TcpClientHandler for HttpUpgradeTcpClientHandler {
    fn has_session_pool(&self) -> bool {
        self.handler.has_session_pool()
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let transport = transport.wrap(|stream| self.setup_client_stream(stream));
        self.handler.connect_client_tcp(transport, target).await
    }

    async fn connect_client_udp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let transport = transport.wrap(|stream| self.setup_client_stream(stream));
        self.handler.connect_client_udp(transport, target).await
    }

    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn crate::resolver::Resolver>,
    ) -> io::Result<ResolvedLocation> {
        self.handler.prepare_target(target, resolver).await
    }

    fn validate_alpn(&self, alpn: Option<&[u8]>) -> io::Result<()> {
        self.handler.validate_alpn(alpn)
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> io::Result<Option<TcpClientSetupResult>> {
        self.handler.try_reuse_tcp_stream(target).await
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let stream = self.setup_client_stream(client_stream).await?;
        self.handler
            .setup_client_tcp_stream(stream, remote_location)
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.handler.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let stream = self.setup_client_stream(client_stream).await?;
        self.handler
            .setup_client_udp_bidirectional(stream, target)
            .await
    }
}

#[derive(Debug)]
pub struct HttpUpgradeServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<FxHashMap<String, String>>,
    pub handler: Box<dyn TcpServerHandler>,
}

impl HttpUpgradeServerTarget {
    pub fn new(
        matching_path: Option<String>,
        matching_headers: Option<FxHashMap<String, String>>,
        handler: Box<dyn TcpServerHandler>,
    ) -> Self {
        let matching_path = matching_path.map(|p| {
            if p.starts_with('/') {
                p
            } else {
                format!("/{p}")
            }
        });
        Self {
            matching_path,
            matching_headers,
            handler,
        }
    }
}

#[derive(Debug)]
pub struct HttpUpgradeTcpServerHandler {
    server_targets: Vec<HttpUpgradeServerTarget>,
}

impl HttpUpgradeTcpServerHandler {
    pub fn new(server_targets: Vec<HttpUpgradeServerTarget>) -> Self {
        Self { server_targets }
    }
}

#[async_trait]
impl TcpServerHandler for HttpUpgradeTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let ParsedHttpData {
            first_line,
            headers: request_headers,
            stream_reader,
        } = match ParsedHttpData::parse(&mut server_stream).await {
            Ok(parsed) => parsed,
            Err(_) => return Err(reject_upgrade(&mut server_stream, "400 Bad Request").await),
        };

        let request_path = first_line
            .strip_prefix("GET ")
            .and_then(|line| line.strip_suffix(" HTTP/1.1").or_else(|| line.strip_suffix(" HTTP/1.0")))
            .filter(|path| path.starts_with('/') && !path.bytes().any(|b| b.is_ascii_whitespace()));

        let valid_host = request_headers.get("host").is_some_and(|host| {
            host.parse::<http::uri::Authority>()
                .is_ok_and(|authority| !authority.host().is_empty())
        });

        if request_path.is_none()
            || !valid_host
            || !has_token(&request_headers, "upgrade", "websocket")
            || !has_token(&request_headers, "connection", "upgrade")
            || request_headers.contains_key("sec-websocket-key")
        {
            return Err(reject_upgrade(&mut server_stream, "400 Bad Request").await);
        }
        let request_path = request_path.unwrap();

        let candidates: Vec<_> = self
            .server_targets
            .iter()
            .filter(|target| {
                let path_matches = match &target.matching_path {
                    Some(path) => path == request_path,
                    None => true,
                };
                path_matches
                    && target.matching_headers.as_ref().is_none_or(|headers| {
                        headers
                            .iter()
                            .all(|(key, value)| request_headers.get(key) == Some(value))
                    })
            })
            .collect();

        let Some(server_target) = candidates.first() else {
            return Err(reject_upgrade(&mut server_stream, "404 Not Found").await);
        };

        let response = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        server_stream.write_all(response.as_bytes()).await?;
        server_stream.flush().await?;

        let unparsed = stream_reader.unparsed_data_owned();
        let stream: Box<dyn AsyncStream> = match unparsed {
            Some(data) => Box::new(PrependStream::new(server_stream, Some(data))),
            None => server_stream,
        };

        let mut result = server_target.handler.setup_server_stream(stream).await?;
        result.set_need_initial_flush(true);
        Ok(result)
    }
}

