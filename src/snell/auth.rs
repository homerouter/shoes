//! Snell server authentication, as sing-snell's `MultiService`: a shared
//! password, a per-request client ID (`userkey`), or per-user PSKs found by
//! trial decryption. sing-snell ranks PSK users by usage; trying them in
//! move-to-front order gives the same result.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::aead::{snell_kdf, Aead};
use super::quic_proxy::{decode_quic_proxy_init, QuicInit};
use super::v6::{SnellV6Mode, V6Codec};
use crate::config::SnellUserConfig;

const SALT_LEN: usize = 16;
/// First length header: 7 sealed bytes and a 16-byte tag.
const HEADER_CIPHER_LEN: usize = 23;
const HEADER_VERSION: u8 = 4;

/// A psk-mode user and the framing its PSK selects.
#[derive(Debug)]
pub struct PskUser {
    pub name: String,
    pub psk: Arc<[u8]>,
    /// v6 framing for this PSK; `None` on v4/v5.
    pub v6: Option<V6Codec>,
}

#[derive(Debug)]
pub enum SnellAuth {
    /// The shared password only (no `users`).
    Single,
    /// Shared password; every request's client ID must name a user.
    UserKey(HashMap<Box<[u8]>, String>),
    /// Per-user PSKs, tried in move-to-front order.
    Psk {
        users: Vec<PskUser>,
        order: Mutex<Vec<usize>>,
    },
}

impl SnellAuth {
    /// Builds from validated config; `v6_mode` is set for a v6 server.
    pub fn new(
        users: &[SnellUserConfig],
        authentication: Option<&str>,
        v6_mode: Option<SnellV6Mode>,
    ) -> Self {
        if users.is_empty() {
            return Self::Single;
        }
        if authentication == Some("psk") {
            let users: Vec<PskUser> = users
                .iter()
                .map(|user| {
                    let psk = user.password.as_deref().unwrap_or_default().as_bytes();
                    PskUser {
                        name: user.name.clone(),
                        psk: Arc::from(psk),
                        v6: v6_mode.map(|mode| V6Codec::new(mode, psk)),
                    }
                })
                .collect();
            let order = Mutex::new((0..users.len()).collect());
            return Self::Psk { users, order };
        }
        Self::UserKey(
            users
                .iter()
                .map(|user| {
                    let key = user.userkey.as_deref().unwrap_or_default().as_bytes();
                    (Box::from(key), user.name.clone())
                })
                .collect(),
        )
    }

    /// userkey mode: the user a request's client ID names. Other modes
    /// accept every request.
    pub fn check_client_id(&self, client_id: &[u8]) -> std::io::Result<Option<&str>> {
        match self {
            Self::UserKey(users) => users.get(client_id).map(|name| Some(name.as_str())).ok_or_else(
                || std::io::Error::new(std::io::ErrorKind::PermissionDenied, "snell: bad user key"),
            ),
            _ => Ok(None),
        }
    }

    pub fn is_psk(&self) -> bool {
        matches!(self, Self::Psk { .. })
    }

    /// psk mode: bytes to read before trying users (salt and first header,
    /// for the longest shape profile).
    pub fn psk_head_len(&self) -> usize {
        let Self::Psk { users, .. } = self else {
            return 0;
        };
        users
            .iter()
            .map(|user| match user.v6.as_ref().and_then(V6Codec::profile) {
                Some(profile) => {
                    profile.salt_block_len() + profile.prefix_len(0) + HEADER_CIPHER_LEN
                }
                None => SALT_LEN + HEADER_CIPHER_LEN,
            })
            .max()
            .unwrap_or(0)
    }

    /// psk mode: the user whose PSK opens the first header in `head`; it
    /// moves to the front of the trial order.
    pub fn match_psk(&self, head: &[u8]) -> Option<&PskUser> {
        self.find_psk(|user| header_opens(user, head).then_some(()))
            .map(|(user, ())| user)
    }

    /// psk mode: the first user, in trial order, for whom `open` succeeds;
    /// it moves to the front of the order.
    fn find_psk<T>(&self, mut open: impl FnMut(&PskUser) -> Option<T>) -> Option<(&PskUser, T)> {
        let Self::Psk { users, order } = self else {
            return None;
        };
        let candidates = order.lock().unwrap().clone();
        let (index, opened) = candidates
            .into_iter()
            .find_map(|i| open(&users[i]).map(|opened| (i, opened)))?;
        let mut order = order.lock().unwrap();
        if let Some(position) = order.iter().position(|&i| i == index) {
            order[..=position].rotate_right(1);
        }
        Some((&users[index], opened))
    }

    /// Opens a QUIC proxy init: with the shared PSK (checking the userkey in
    /// userkey mode) or, in psk mode, each user's PSK. sing-snell
    /// `MultiService.ParseQUICProxyInit`; the parser rejects an empty payload.
    pub fn open_quic_init(&self, shared_psk: &Arc<[u8]>, data: &[u8]) -> std::io::Result<QuicInit> {
        let (psk, (target, _, payload), user) = if self.is_psk() {
            let (user, opened) = self
                .find_psk(|user| decode_quic_proxy_init(&user.psk, data).ok())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "snell: authentication failed: no matching PSK",
                    )
                })?;
            (user.psk.clone(), opened, Some(user.name.clone()))
        } else {
            let opened = decode_quic_proxy_init(shared_psk, data)?;
            let user = self.check_client_id(&opened.1)?.map(str::to_owned);
            (shared_psk.clone(), opened, user)
        };
        Ok(QuicInit {
            psk,
            target,
            payload,
            user,
        })
    }
}

/// True when `user`'s PSK decrypts the first length header in `head`.
fn header_opens(user: &PskUser, head: &[u8]) -> bool {
    let profile = user.v6.as_ref().and_then(V6Codec::profile);
    let (salt, prefix, header) = match profile {
        Some(profile) => {
            let block = profile.salt_block_len();
            let end = block + profile.prefix_len(0);
            if head.len() < end + HEADER_CIPHER_LEN {
                return false;
            }
            (
                profile.read_salt_block(&head[..block]),
                &head[block..end],
                &head[end..end + HEADER_CIPHER_LEN],
            )
        }
        None => {
            if head.len() < SALT_LEN + HEADER_CIPHER_LEN {
                return false;
            }
            (
                head[..SALT_LEN].try_into().unwrap(),
                &head[..0],
                &head[SALT_LEN..SALT_LEN + HEADER_CIPHER_LEN],
            )
        }
    };
    let aead = Aead::aes_128_gcm(&snell_kdf(&user.psk, &salt, 16));
    let mut plain = header[..7].to_vec();
    aead.open_detached(&[0; 12], prefix, &mut plain, &header[7..]).is_ok()
        && plain[0] == HEADER_VERSION
}

