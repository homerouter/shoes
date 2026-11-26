use std::io;
use std::sync::Arc;

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
    /// Bounds concurrent memory-hard verifications so a flood cannot exhaust RAM.
    argon2_slots: Arc<tokio::sync::Semaphore>,
}

impl MasqueAuth {
    pub fn from_users(users: &[MasqueUserConfig], stealth_404: bool) -> io::Result<Self> {
        let mut configured = Vec::with_capacity(users.len());
        for user in users {
            let secret = if user.password.starts_with("$argon2id$") {
                validate_argon2id_phc(&user.password).map_err(|err| {
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
        let slots = std::thread::available_parallelism().map_or(2, |n| n.get());
        Ok(Self {
            users: configured,
            stealth_404,
            argon2_slots: Arc::new(tokio::sync::Semaphore::new(slots)),
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

    pub async fn verify_headers(
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

        let user = self
            .users
            .iter()
            .find(|user| bool::from(user.username.as_bytes().ct_eq(username.as_bytes())));
        let valid = match user.map(|user| &user.secret) {
            Some(StoredSecret::Plain(expected)) => {
                bool::from(expected.as_bytes().ct_eq(password.as_bytes()))
            }
            Some(StoredSecret::Argon2id(encoded)) => self.verify_argon2(encoded, password).await,
            None => {
                // Pay the same KDF cost for unknown names so timing does not reveal valid ones.
                if let Some(encoded) = self.users.iter().find_map(|user| match &user.secret {
                    StoredSecret::Argon2id(encoded) => Some(encoded),
                    StoredSecret::Plain(_) => None,
                }) {
                    self.verify_argon2(encoded, password).await;
                }
                false
            }
        };
        match user {
            Some(user) if valid => Ok(Some(user.username.clone())),
            _ => Err(self.rejection()),
        }
    }

    /// Runs the memory-hard KDF off the async workers.
    async fn verify_argon2(&self, encoded: &str, password: &str) -> bool {
        let Ok(_slot) = self.argon2_slots.acquire().await else {
            return false;
        };
        let (encoded, password) = (encoded.to_owned(), password.to_owned());
        tokio::task::spawn_blocking(move || {
            argon2::verify_encoded(&encoded, password.as_bytes()).unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }
}

/// Validates PHC structure and Argon2id bounds without executing the memory-hard KDF.
fn validate_argon2id_phc(encoded: &str) -> Result<(), &'static str> {
    let parts: Vec<&str> = encoded.split('$').collect();
    let (params_str, salt_b64, hash_b64) = match parts.as_slice() {
        ["", "argon2id", version, params, salt, hash] => {
            if !matches!(*version, "v=16" | "v=19") {
                return Err("unsupported argon2 version");
            }
            (*params, *salt, *hash)
        }
        ["", "argon2id", params, salt, hash] => (*params, *salt, *hash),
        _ => return Err("malformed PHC string"),
    };

    let mut params = params_str.split(',');
    let (Some(m_part), Some(t_part), Some(p_part), None) =
        (params.next(), params.next(), params.next(), params.next())
    else {
        return Err("malformed argon2 parameters");
    };

    let mem_cost: u32 = m_part
        .strip_prefix("m=")
        .and_then(|v| v.parse().ok())
        .ok_or("invalid memory cost")?;
    let time_cost: u32 = t_part
        .strip_prefix("t=")
        .and_then(|v| v.parse().ok())
        .ok_or("invalid time cost")?;
    let lanes: u32 = p_part
        .strip_prefix("p=")
        .and_then(|v| v.parse().ok())
        .ok_or("invalid parallelism")?;

    // Operator-typo guards: verification allocates m KiB and may use p threads.
    if !(1..=64).contains(&lanes) {
        return Err("parallelism out of range");
    }
    if mem_cost < 8
        || u64::from(mem_cost) < 8 * u64::from(lanes)
        || mem_cost > 0x40_0000
        || (cfg!(target_pointer_width = "32") && mem_cost > 0x20_0000)
    {
        return Err("memory cost out of range");
    }
    if time_cost < 1 {
        return Err("time cost out of range");
    }

    let salt = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(salt_b64)
        .map_err(|_| "invalid base64 salt")?;
    if salt.len() < 8 {
        return Err("salt too short");
    }

    let hash = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(hash_b64)
        .map_err(|_| "invalid base64 hash")?;
    if hash.len() < 4 {
        return Err("hash too short");
    }

    Ok(())
}
