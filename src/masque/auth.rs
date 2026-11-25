use std::io;

use base64::Engine;
use http::{HeaderMap, Response, StatusCode, header};
use subtle::ConstantTimeEq;

use crate::config::MasqueUserConfig;

#[derive(Debug, Clone)]
enum StoredSecret {
    Plain(String),
    Argon2id(String),
}

#[derive(Debug, Clone)]
struct ConfiguredUser {
    username: String,
    secret: StoredSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRejection {
    stealth_404: bool,
}

impl AuthRejection {
    pub fn status_code(&self) -> StatusCode {
        if self.stealth_404 {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::PROXY_AUTHENTICATION_REQUIRED
        }
    }

    pub fn into_response(self) -> Response<()> {
        let mut builder = Response::builder().status(self.status_code());
        if !self.stealth_404 {
            builder = builder.header(header::PROXY_AUTHENTICATE, "Basic realm=\"shoes\"");
        }
        builder.body(()).expect("valid auth rejection response")
    }
}

#[derive(Debug, Clone)]
pub struct MasqueAuth {
    users: Vec<ConfiguredUser>,
    stealth_404: bool,
}

impl MasqueAuth {
    pub fn from_users(users: &[MasqueUserConfig], stealth_404: bool) -> io::Result<Self> {
        let mut configured = Vec::with_capacity(users.len());
        for user in users {
            let secret = if user.password.starts_with("$argon2id$") {
                argon2::verify_encoded(&user.password, b"").map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid MASQUE argon2id hash for {}: {err}", user.username),
                    )
                })?;
                StoredSecret::Argon2id(user.password.clone())
            } else {
                StoredSecret::Plain(user.password.clone())
            };
            configured.push(ConfiguredUser {
                username: user.username.clone(),
                secret,
            });
        }
        Ok(Self {
            users: configured,
            stealth_404,
        })
    }

    pub fn has_users(&self) -> bool {
        !self.users.is_empty()
    }

    pub fn rejection(&self) -> AuthRejection {
        AuthRejection {
            stealth_404: self.stealth_404,
        }
    }

    pub fn verify_headers(
        &self,
        headers: &HeaderMap,
        allow_authorization: bool,
        peer_authenticated_by_mtls: bool,
    ) -> Result<Option<String>, AuthRejection> {
        if !self.has_users() {
            return if peer_authenticated_by_mtls {
                Ok(None)
            } else {
                Err(self.rejection())
            };
        }

        let mut proxy_values = headers.get_all(header::PROXY_AUTHORIZATION).iter();
        let proxy_val = proxy_values.next();
        if proxy_values.next().is_some() {
            return Err(self.rejection());
        }

        let header_value = if allow_authorization {
            let mut auth_values = headers.get_all(header::AUTHORIZATION).iter();
            let auth_val = auth_values.next();
            if auth_values.next().is_some() {
                return Err(self.rejection());
            }
            // RFC 9484 Section 11: reject if both Proxy-Authorization and Authorization are sent.
            if proxy_val.is_some() && auth_val.is_some() {
                return Err(self.rejection());
            }
            proxy_val.or(auth_val)
        } else {
            proxy_val
        }
        .ok_or_else(|| self.rejection())?;

        let raw = header_value.as_bytes();
        if raw.len() < 6 || !raw[..6].eq_ignore_ascii_case(b"Basic ") {
            return Err(self.rejection());
        }

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&raw[6..])
            .map_err(|_| self.rejection())?;
        let credentials = std::str::from_utf8(&decoded).map_err(|_| self.rejection())?;
        let (username, password) = credentials.split_once(':').ok_or_else(|| self.rejection())?;

        for user in &self.users {
            if bool::from(user.username.as_bytes().ct_eq(username.as_bytes())) {
                let valid = match &user.secret {
                    StoredSecret::Plain(expected) => {
                        bool::from(expected.as_bytes().ct_eq(password.as_bytes()))
                    }
                    StoredSecret::Argon2id(encoded) => {
                        argon2::verify_encoded(encoded, password.as_bytes()).unwrap_or(false)
                    }
                };
                if valid {
                    return Ok(Some(user.username.clone()));
                }
                return Err(self.rejection());
            }
        }

        Err(self.rejection())
    }
}
