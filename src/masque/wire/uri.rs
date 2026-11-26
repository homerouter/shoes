use std::collections::HashSet;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};

use super::WireError;

/// Parsed CONNECT-UDP target from the URI template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHostPort {
    pub host: String,
    pub port: u16,
}

/// Parsed CONNECT-IP target from the URI template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpTunnelTarget {
    pub target: Option<String>,
    pub ipproto: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UdpVar {
    Host,
    Port,
}

impl UdpVar {
    fn parse(name: &str) -> Result<Self, WireError> {
        match name {
            "target_host" => Ok(Self::Host),
            "target_port" => Ok(Self::Port),
            other => Err(WireError::InvalidTemplate(format!(
                "unsupported CONNECT-UDP variable: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpVar {
    Target,
    Protocol,
}

impl IpVar {
    fn parse(name: &str) -> Result<Self, WireError> {
        match name {
            "target" => Ok(Self::Target),
            "ipproto" => Ok(Self::Protocol),
            other => Err(WireError::InvalidTemplate(format!(
                "unsupported CONNECT-IP variable: {other}"
            ))),
        }
    }
}

#[derive(Debug)]
enum Component<V> {
    Literal(Box<str>),
    Variable(V),
}

#[derive(Debug)]
struct QueryParam<V> {
    name: Box<str>,
    value: Component<V>,
    optional: bool,
}

#[derive(Debug)]
struct CompiledTemplate<V> {
    path: Vec<Component<V>>,
    query: Vec<QueryParam<V>>,
}

impl<V: Copy + Eq + Hash> CompiledTemplate<V> {
    fn parse(template: &str, parse_var: fn(&str) -> Result<V, WireError>) -> Result<(Self, HashSet<V>), WireError> {
        if !template.starts_with('/')
            || template.starts_with("//")
            || template.contains('#')
            || !template.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(WireError::InvalidTemplate(
                "template must be an ASCII relative path starting with '/'".into(),
            ));
        }

        let mut variables = HashSet::new();
        let mut names = HashSet::new();
        let mut query = Vec::new();

        let (fixed, expansion) =
            if let Some(start) = template.find("{?").or_else(|| template.find("{&")) {
                let expression = template[start + 2..]
                    .strip_suffix('}')
                    .ok_or_else(|| WireError::InvalidTemplate("unclosed query expansion".into()))?;
                let fixed = &template[..start];
                if (template.as_bytes()[start + 1] == b'&') != fixed.contains('?') {
                    return Err(WireError::InvalidTemplate(
                        "mismatched query expansion operator".into(),
                    ));
                }
                (fixed, Some(expression))
            } else {
                (template, None)
            };

        let (path_str, fixed_query) = fixed
            .split_once('?')
            .map_or((fixed, None), |(p, q)| (p, Some(q)));

        let path = path_str
            .split('/')
            .map(|part| parse_component(part, &mut variables, parse_var))
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(fixed_query) = fixed_query {
            for pair in fixed_query.split('&') {
                let (name, value) = pair
                    .split_once('=')
                    .ok_or_else(|| WireError::InvalidTemplate("malformed query parameter".into()))?;
                if name.is_empty()
                    || name.contains(['{', '}'])
                    || percent_decode_strict(name).is_none()
                    || !names.insert(name)
                {
                    return Err(WireError::InvalidTemplate(
                        "invalid or duplicate query parameter name".into(),
                    ));
                }
                query.push(QueryParam {
                    name: name.into(),
                    value: parse_component(value, &mut variables, parse_var)?,
                    optional: false,
                });
            }
        }

        if let Some(expansion) = expansion {
            for name in expansion.split(',') {
                let var = parse_var(name)?;
                if !variables.insert(var) || !names.insert(name) {
                    return Err(WireError::InvalidTemplate(
                        "duplicate variable in query expansion".into(),
                    ));
                }
                query.push(QueryParam {
                    name: name.into(),
                    value: Component::Variable(var),
                    optional: true,
                });
            }
        }

        Ok((Self { path, query }, variables))
    }

    /// Match raw request path+query against the template structure.
    ///
    /// Returns `Ok(None)` on path/query structural mismatch (404), or
    /// `Ok(Some(captured))` when the template structure matches.
    fn match_structure<'a>(&self, raw_path: &'a str) -> Option<Vec<(V, &'a str)>> {
        if raw_path.contains('#') || !raw_path.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return None;
        }
        let (path_str, query_str) = raw_path
            .split_once('?')
            .map_or((raw_path, None), |(p, q)| (p, Some(q)));

        let mut captured = Vec::new();
        let mut segments = path_str.split('/');
        for component in &self.path {
            let seg = segments.next()?;
            match component {
                Component::Literal(lit) => {
                    if lit.as_ref() != seg {
                        return None;
                    }
                }
                Component::Variable(var) => captured.push((*var, seg)),
            }
        }
        if segments.next().is_some() {
            return None;
        }

        let mut seen = HashSet::new();
        if let Some(query_str) = query_str {
            for pair in query_str.split('&') {
                let (name, value) = pair.split_once('=')?;
                let param = self.query.iter().find(|p| p.name.as_ref() == name)?;
                if !seen.insert(name) {
                    return None;
                }
                match &param.value {
                    Component::Literal(lit) => {
                        if lit.as_ref() != value {
                            return None;
                        }
                    }
                    Component::Variable(var) => captured.push((*var, value)),
                }
            }
        }

        if self
            .query
            .iter()
            .any(|p| !p.optional && !seen.contains(p.name.as_ref()))
        {
            return None;
        }

        Some(captured)
    }
}

fn parse_component<V: Copy + Eq + Hash>(
    value: &str,
    variables: &mut HashSet<V>,
    parse_var: fn(&str) -> Result<V, WireError>,
) -> Result<Component<V>, WireError> {
    if let Some(name) = value.strip_prefix('{').and_then(|v| v.strip_suffix('}')) {
        let var = parse_var(name)?;
        if !variables.insert(var) {
            return Err(WireError::InvalidTemplate(
                "duplicate template variable".into(),
            ));
        }
        Ok(Component::Variable(var))
    } else if value.contains(['{', '}']) || percent_decode_strict(value).is_none() {
        Err(WireError::InvalidTemplate(
            "invalid literal component in URI template".into(),
        ))
    } else {
        Ok(Component::Literal(value.into()))
    }
}

#[derive(Debug)]
pub struct UdpUriTemplate(CompiledTemplate<UdpVar>);

impl UdpUriTemplate {
    pub fn parse(template: &str) -> std::io::Result<Self> {
        let (compiled, vars) = CompiledTemplate::parse(template, UdpVar::parse)?;
        if !vars.contains(&UdpVar::Host) || !vars.contains(&UdpVar::Port) {
            return Err(WireError::InvalidTemplate(
                "CONNECT-UDP template must contain {target_host} and {target_port}".into(),
            )
            .into());
        }
        Ok(Self(compiled))
    }

    pub fn match_path(&self, raw_path: &str) -> Result<Option<TargetHostPort>, WireError> {
        let Some(captured) = self.0.match_structure(raw_path) else {
            return Ok(None);
        };
        let mut host = None;
        let mut port = None;
        for (var, val) in captured {
            match var {
                UdpVar::Host => host = Some(parse_udp_host(val)?),
                UdpVar::Port => port = Some(parse_udp_port(val)?),
            }
        }
        let (Some(host), Some(port)) = (host, port) else {
            return Ok(None);
        };
        Ok(Some(TargetHostPort { host, port }))
    }
}

#[derive(Debug)]
pub struct IpUriTemplate(CompiledTemplate<IpVar>);

impl IpUriTemplate {
    pub fn parse(template: &str) -> std::io::Result<Self> {
        let (compiled, _) = CompiledTemplate::parse(template, IpVar::parse)?;
        Ok(Self(compiled))
    }

    pub fn match_path(&self, raw_path: &str) -> Result<Option<IpTunnelTarget>, WireError> {
        let Some(captured) = self.0.match_structure(raw_path) else {
            return Ok(None);
        };
        let mut out = IpTunnelTarget {
            target: None,
            ipproto: None,
        };
        for (var, val) in captured {
            match var {
                IpVar::Target => out.target = parse_ip_target(val)?,
                IpVar::Protocol => out.ipproto = parse_ip_protocol(val)?,
            }
        }
        Ok(Some(out))
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode strictly once, rejecting truncated/malformed escapes and non-UTF-8.
fn percent_decode_strict(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(if byte == b'%' {
            (hex_digit(bytes.next()?)? << 4) | hex_digit(bytes.next()?)?
        } else {
            byte
        });
    }
    String::from_utf8(decoded).ok()
}

fn is_rfc3986_reg_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b))
}

fn parse_udp_host(value: &str) -> Result<String, WireError> {
    if value.contains([':', '/']) {
        return Err(WireError::InvalidTarget);
    }
    let decoded = percent_decode_strict(value).ok_or(WireError::InvalidTarget)?;
    if decoded.is_empty() {
        return Err(WireError::InvalidTarget);
    }
    if let Some(inner) = decoded.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let addr: Ipv6Addr = inner.parse().map_err(|_| WireError::InvalidTarget)?;
        return Ok(addr.to_string());
    }
    if decoded.contains(':') {
        decoded
            .parse::<Ipv6Addr>()
            .map_err(|_| WireError::InvalidTarget)?;
        return Ok(decoded);
    }
    if !is_rfc3986_reg_name(&decoded) {
        return Err(WireError::InvalidTarget);
    }
    Ok(decoded)
}

fn parse_udp_port(value: &str) -> Result<u16, WireError> {
    let decoded =
        percent_decode_strict(value).ok_or_else(|| WireError::InvalidPort(value.into()))?;
    let port = decoded
        .parse::<u16>()
        .map_err(|_| WireError::InvalidPort(decoded.clone()))?;
    if port == 0 {
        return Err(WireError::InvalidPort("0".into()));
    }
    Ok(port)
}

fn parse_ip_protocol(value: &str) -> Result<Option<u8>, WireError> {
    let invalid = || WireError::InvalidProtocol(value.into());
    let decoded = percent_decode_strict(value).ok_or_else(invalid)?;
    if decoded == "*" {
        return Ok(None);
    }
    if decoded.is_empty() || decoded.len() > 3 || !decoded.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    decoded.parse::<u8>().map(Some).map_err(|_| invalid())
}

fn parse_ip_target(value: &str) -> Result<Option<String>, WireError> {
    if value.contains([':', '/']) {
        return Err(WireError::InvalidTarget);
    }
    let decoded = percent_decode_strict(value).ok_or(WireError::InvalidTarget)?;
    if decoded == "*" {
        return Ok(None);
    }
    if decoded.is_empty() {
        return Err(WireError::InvalidTarget);
    }
    if let Some((address, prefix)) = decoded.split_once('/') {
        let address: IpAddr = address.parse().map_err(|_| WireError::InvalidTarget)?;
        let max_digits = if address.is_ipv4() { 2 } else { 3 };
        if prefix.is_empty()
            || prefix.len() > max_digits
            || !prefix.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(WireError::InvalidTarget);
        }
        let prefix: u8 = prefix.parse().map_err(|_| WireError::InvalidTarget)?;
        let network =
            ipnetwork::IpNetwork::new(address, prefix).map_err(|_| WireError::InvalidTarget)?;
        if network.network() != address {
            return Err(WireError::InvalidTarget);
        }
    } else if decoded.contains(':') {
        decoded
            .parse::<Ipv6Addr>()
            .map_err(|_| WireError::InvalidTarget)?;
    } else if !is_rfc3986_reg_name(&decoded) {
        return Err(WireError::InvalidTarget);
    }
    Ok(Some(decoded))
}
