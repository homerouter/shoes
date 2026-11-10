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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::AsyncStream;
    use crate::snell::v4::V4Conn;
    use crate::snell::v6::V6Conn;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn user(name: &str, userkey: Option<&str>, password: Option<&str>) -> SnellUserConfig {
        SnellUserConfig {
            name: name.into(),
            userkey: userkey.map(Into::into),
            password: password.map(Into::into),
        }
    }

    /// The first bytes a client sends with `psk` (v6 when `mode` is set).
    async fn client_head(psk: &[u8], mode: Option<SnellV6Mode>) -> Vec<u8> {
        let (io, mut tap) = duplex(1 << 16);
        let io: Box<dyn AsyncStream> = Box::new(io);
        match mode {
            Some(mode) => {
                let mut conn = V6Conn::new(io, Arc::from(psk), V6Codec::new(mode, psk));
                conn.write_all(b"\x01\x05\x00request").await.unwrap();
                conn.flush().await.unwrap();
            }
            None => {
                let mut conn = V4Conn::new(io, Arc::from(psk));
                conn.write_all(b"\x01\x05\x00request").await.unwrap();
                conn.flush().await.unwrap();
            }
        }
        let mut bytes = Vec::new();
        tap.read_to_end(&mut bytes).await.unwrap();
        bytes
    }

    #[test]
    fn userkey_names_the_user() {
        let auth = SnellAuth::new(
            &[user("alice", Some("alice-key"), None), user("bob", Some("bob-key"), None)],
            None,
            None,
        );
        assert_eq!(auth.check_client_id(b"bob-key").unwrap(), Some("bob"));
        let error = auth.check_client_id(b"mallory").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "snell: bad user key");
        assert!(auth.check_client_id(b"").is_err());
    }

    #[test]
    fn single_and_psk_accept_any_client_id() {
        assert_eq!(SnellAuth::new(&[], None, None).check_client_id(b"x").unwrap(), None);
        let auth = SnellAuth::new(&[user("a", None, Some("a-psk"))], Some("psk"), None);
        assert_eq!(auth.check_client_id(b"x").unwrap(), None);
    }

    #[tokio::test]
    async fn psk_v4_finds_the_user_and_moves_it_to_front() {
        let users = [
            user("a", None, Some("a-psk-123456")),
            user("b", None, Some("b-psk-123456")),
            user("c", None, Some("c-psk-123456")),
        ];
        let auth = SnellAuth::new(&users, Some("psk"), None);
        assert!(auth.is_psk());
        assert_eq!(auth.psk_head_len(), 39);
        let head = client_head(b"c-psk-123456", None).await;
        assert_eq!(auth.match_psk(&head).unwrap().name, "c");
        let SnellAuth::Psk { order, .. } = &auth else { unreachable!() };
        assert_eq!(*order.lock().unwrap(), [2, 0, 1]);
        let head = client_head(b"nobody-psk-1", None).await;
        assert!(auth.match_psk(&head).is_none());
        assert!(auth.match_psk(&head[..10]).is_none());
    }

    #[tokio::test]
    async fn psk_v6_finds_the_user_in_each_authenticated_mode() {
        for mode in [SnellV6Mode::Default, SnellV6Mode::Unshaped] {
            let users = [
                user("a", None, Some("a-psk-123456")),
                user("b", None, Some("b-psk-123456")),
            ];
            let auth = SnellAuth::new(&users, Some("psk"), Some(mode));
            let head = client_head(b"b-psk-123456", Some(mode)).await;
            assert!(head.len() >= auth.psk_head_len(), "{mode:?}");
            assert_eq!(auth.match_psk(&head).unwrap().name, "b", "{mode:?}");
            let head = client_head(b"nobody-psk-1", Some(mode)).await;
            assert!(auth.match_psk(&head).is_none(), "{mode:?}");
        }
    }

    #[test]
    fn quic_init_is_authenticated_like_tcp() {
        use crate::address::NetLocation;
        use crate::snell::quic_proxy::encode_quic_proxy_init;

        let target = NetLocation::from_str("127.0.0.1:443", None).unwrap();
        let init = |psk: &[u8], key: &[u8], payload: &[u8]| {
            encode_quic_proxy_init(psk, key, &target, payload).unwrap()
        };
        let shared: Arc<[u8]> = Arc::from(&b"shared-psk"[..]);

        let single = SnellAuth::new(&[], None, None);
        let opened = single.open_quic_init(&shared, &init(b"shared-psk", b"", b"\xc0hi")).unwrap();
        assert_eq!(opened.target, target);
        assert_eq!(opened.payload, b"\xc0hi");
        assert_eq!(opened.user, None);
        assert!(Arc::ptr_eq(&opened.psk, &shared));
        let error = single.open_quic_init(&shared, &init(b"shared-psk", b"", b"")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "snell quic proxy: init request does not contain a payload"
        );
        assert!(single.open_quic_init(&shared, &init(b"other-psk", b"", b"x")).is_err());

        let userkey = SnellAuth::new(&[user("alice", Some("alice-key"), None)], None, None);
        let opened =
            userkey.open_quic_init(&shared, &init(b"shared-psk", b"alice-key", b"x")).unwrap();
        assert_eq!(opened.user.as_deref(), Some("alice"));
        let error =
            userkey.open_quic_init(&shared, &init(b"shared-psk", b"mallory", b"x")).unwrap_err();
        assert_eq!(error.to_string(), "snell: bad user key");

        let users = [user("a", None, Some("a-psk-123456")), user("b", None, Some("b-psk-123456"))];
        let psk = SnellAuth::new(&users, Some("psk"), None);
        let opened = psk.open_quic_init(&shared, &init(b"b-psk-123456", b"", b"x")).unwrap();
        assert_eq!(opened.user.as_deref(), Some("b"));
        assert_eq!(&*opened.psk, b"b-psk-123456");
        let SnellAuth::Psk { order, .. } = &psk else { unreachable!() };
        assert_eq!(*order.lock().unwrap(), [1, 0]);
        let error = psk.open_quic_init(&shared, &init(b"nobody-psk-1", b"", b"x")).unwrap_err();
        assert_eq!(error.to_string(), "snell: authentication failed: no matching PSK");
    }
}
