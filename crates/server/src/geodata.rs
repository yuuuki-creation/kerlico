use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Catalog {
    inner: Arc<Mutex<State>>,
}

struct State {
    dir: PathBuf,
    sites: BTreeMap<String, Vec<Dom>>,
    nets: BTreeMap<String, Vec<Net>>,
    files: BTreeMap<String, FileData>,
}

struct FileData {
    sites: BTreeMap<String, Vec<Dom>>,
    nets: BTreeMap<String, Vec<Net>>,
}

#[derive(Clone)]
struct Dom {
    kind: u8,
    value: String,
}

#[derive(Clone)]
struct Net {
    ip: Vec<u8>,
    prefix: u32,
}

impl Catalog {
    pub fn empty() -> Self {
        Self { inner: Arc::new(Mutex::new(State { dir: PathBuf::new(), sites: BTreeMap::new(), nets: BTreeMap::new(), files: BTreeMap::new() })) }
    }

    pub fn load(dir: &Path) -> Self {
        let sites = read_map(dir.join("geosite.dat"), parse_sites);
        let nets = read_map(dir.join("geoip.dat"), parse_nets);
        Self {
            inner: Arc::new(Mutex::new(State {
                dir: dir.to_path_buf(),
                sites,
                nets,
                files: BTreeMap::new(),
            })),
        }
    }

    pub fn reload(&self, dir: &Path) {
        let loaded = Self::load(dir);
        let mut replacement = loaded.inner.lock().expect("geodata");
        std::mem::swap(&mut *self.inner.lock().expect("geodata"), &mut *replacement);
    }

    pub fn network_set(&self, file: &str, category: &str) -> std::io::Result<kerlico_shared::runtime::GeoIpSet> {
        let mut state = self.inner.lock().expect("geodata");
        let category = category.to_ascii_lowercase();
        let nets = if file == "geoip.dat" {
            state.nets.get(&category)
        } else {
            remember(&mut state, file);
            state.files.get(file).and_then(|data| data.nets.get(&category))
        }.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("GeoIP category {file}:{category} is missing")))?;
        let has_ipv4 = nets.iter().any(|net| net.ip.len() == 4);
        let has_ipv6 = nets.iter().any(|net| net.ip.len() == 16);
        drop(state);
        let catalog = self.clone();
        let file = file.to_owned();
        Ok(kerlico_shared::runtime::GeoIpSet::new(has_ipv4, has_ipv6, move |ip| {
            if file == "geoip.dat" { catalog.net_hit(&category, ip) } else { catalog.ext_net(&file, &category, ip) }
        }))
    }

    pub fn site_hit(&self, category: &str, name: &str) -> bool {
        let state = self.inner.lock().expect("geodata");
        hit_site(state.sites.get(&category.to_ascii_lowercase()), name)
    }

    pub fn has_net(&self, category: &str) -> bool {
        self.inner
            .lock()
            .expect("geodata")
            .nets
            .contains_key(&category.to_ascii_lowercase())
    }

    pub fn net_hit(&self, category: &str, ip: IpAddr) -> bool {
        let state = self.inner.lock().expect("geodata");
        hit_net(state.nets.get(&category.to_ascii_lowercase()), ip)
    }

    pub fn ext_site(&self, file: &str, category: &str, name: &str) -> bool {
        let mut state = self.inner.lock().expect("geodata");
        remember(&mut state, file);
        let Some(data) = state.files.get(file) else {
            return false;
        };
        hit_site(data.sites.get(&category.to_ascii_lowercase()), name)
    }

    pub fn ext_has_net(&self, file: &str, category: &str) -> bool {
        let mut state = self.inner.lock().expect("geodata");
        remember(&mut state, file);
        state
            .files
            .get(file)
            .is_some_and(|data| data.nets.contains_key(&category.to_ascii_lowercase()))
    }

    pub fn ext_net(&self, file: &str, category: &str, ip: IpAddr) -> bool {
        let mut state = self.inner.lock().expect("geodata");
        remember(&mut state, file);
        let Some(data) = state.files.get(file) else {
            return false;
        };
        hit_net(data.nets.get(&category.to_ascii_lowercase()), ip)
    }
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.debug_struct("GeoIpCatalog").finish_non_exhaustive() }
}
impl kerlico_shared::runtime::GeoIpCatalog for Catalog {
    fn load(&self, file: &str, category: &str) -> std::io::Result<kerlico_shared::runtime::GeoIpSet> { self.network_set(file, category) }
}

fn remember(state: &mut State, file: &str) {
    if state.files.contains_key(file) {
        return;
    }
    let path = state.dir.join(file);
    let buf = std::fs::read(path).unwrap_or_default();
    state.files.insert(
        file.to_string(),
        FileData {
            sites: parse_sites(&buf),
            nets: parse_nets(&buf),
        },
    );
}

fn read_map<T>(path: PathBuf, parse: fn(&[u8]) -> BTreeMap<String, Vec<T>>) -> BTreeMap<String, Vec<T>> {
    std::fs::read(path).map(|buf| parse(&buf)).unwrap_or_default()
}

fn hit_site(domains: Option<&Vec<Dom>>, name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    domains
        .into_iter()
        .flatten()
        .any(|dom| domain_hit(dom, &name))
}

fn hit_net(nets: Option<&Vec<Net>>, ip: IpAddr) -> bool {
    nets.into_iter().flatten().any(|net| net_contains(net, ip))
}

fn domain_hit(dom: &Dom, name: &str) -> bool {
    let value = dom.value.to_ascii_lowercase();
    match dom.kind {
        3 => name == value,
        2 => name == value || name.ends_with(&format!(".{value}")),
        1 => regex::Regex::new(&dom.value).is_ok_and(|pattern| pattern.is_match(name)),
        _ => !value.is_empty() && name.contains(&value),
    }
}

fn net_contains(net: &Net, ip: IpAddr) -> bool {
    let bytes = match ip {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    };
    if net.ip.len() != bytes.len() {
        return false;
    }
    let width = (bytes.len() * 8) as u32;
    let prefix = net.prefix.min(width) as usize;
    let full = prefix / 8;
    if net.ip[..full] != bytes[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    net.ip[full] & mask == bytes[full] & mask
}

fn parse_sites(buf: &[u8]) -> BTreeMap<String, Vec<Dom>> {
    let mut map = BTreeMap::new();
    let mut cursor = Cursor { data: buf, at: 0 };
    while let Some((field, payload)) = cursor.next() {
        if field == 1 {
            if let Payload::Bytes(body) = payload {
                if let Some((code, domains)) = parse_site(&body) {
                    map.insert(code.to_ascii_lowercase(), domains);
                }
            }
        }
    }
    map
}

fn parse_site(buf: &[u8]) -> Option<(String, Vec<Dom>)> {
    let mut code = String::new();
    let mut domains = Vec::new();
    let mut cursor = Cursor { data: buf, at: 0 };
    while let Some((field, payload)) = cursor.next() {
        match (field, payload) {
            (1, Payload::Bytes(body)) => code = String::from_utf8(body).ok()?,
            (2, Payload::Bytes(body)) => {
                if let Some(dom) = parse_domain(&body) {
                    domains.push(dom);
                }
            }
            _ => {}
        }
    }
    if code.is_empty() {
        None
    } else {
        Some((code, domains))
    }
}

fn parse_domain(buf: &[u8]) -> Option<Dom> {
    let mut kind = 0u8;
    let mut value = String::new();
    let mut cursor = Cursor { data: buf, at: 0 };
    while let Some((field, payload)) = cursor.next() {
        match (field, payload) {
            (1, Payload::Varint(raw)) => kind = raw as u8,
            (2, Payload::Bytes(body)) => value = String::from_utf8(body).ok()?,
            _ => {}
        }
    }
    if value.is_empty() || value.bytes().any(|byte| byte == 0) {
        None
    } else {
        Some(Dom { kind, value })
    }
}

fn parse_nets(buf: &[u8]) -> BTreeMap<String, Vec<Net>> {
    let mut map: BTreeMap<String, Vec<Net>> = BTreeMap::new();
    let mut cursor = Cursor { data: buf, at: 0 };
    while let Some((field, payload)) = cursor.next() {
        if field == 1 {
            if let Payload::Bytes(body) = payload {
                if let Some((code, nets)) = parse_ip_entry(&body) {
                    map.entry(code.to_ascii_lowercase()).or_default().extend(nets);
                }
            }
        }
    }
    map.retain(|_, nets| !nets.is_empty());
    map
}

fn parse_ip_entry(buf: &[u8]) -> Option<(String, Vec<Net>)> {
    let mut code = String::new();
    let mut nets = Vec::new();
    let mut cursor = Cursor { data: buf, at: 0 };
    while let Some((field, payload)) = cursor.next() {
        match (field, payload) {
            (1, Payload::Bytes(body)) => code = String::from_utf8(body).ok()?,
            (2, Payload::Bytes(body)) => {
                if let Some(net) = parse_cidr(&body) {
                    nets.push(net);
                }
            }
            _ => {}
        }
    }
    if code.is_empty() {
        None
    } else {
        Some((code, nets))
    }
}

fn parse_cidr(buf: &[u8]) -> Option<Net> {
    let mut ip = Vec::new();
    let mut prefix = 0u32;
    let mut cursor = Cursor { data: buf, at: 0 };
    while let Some((field, payload)) = cursor.next() {
        match (field, payload) {
            (1, Payload::Bytes(body)) => ip = body,
            (2, Payload::Varint(raw)) => prefix = raw as u32,
            _ => {}
        }
    }
    if ip.len() == 4 || ip.len() == 16 {
        Some(Net { ip, prefix })
    } else {
        None
    }
}

enum Payload {
    Varint(u64),
    Bytes(Vec<u8>),
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn next(&mut self) -> Option<(u32, Payload)> {
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        match (key & 7) as u8 {
            0 => Some((field, Payload::Varint(self.varint()?))),
            1 => {
                self.at = self.at.checked_add(8)?;
                self.next()
            }
            2 => {
                let len = self.varint()? as usize;
                let end = self.at.checked_add(len)?;
                if end > self.data.len() {
                    return None;
                }
                let bytes = self.data[self.at..end].to_vec();
                self.at = end;
                Some((field, Payload::Bytes(bytes)))
            }
            5 => {
                self.at = self.at.checked_add(4)?;
                self.next()
            }
            _ => None,
        }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut out = 0u64;
        let mut shift = 0;
        loop {
            if self.at >= self.data.len() || shift > 63 {
                return None;
            }
            let byte = self.data[self.at];
            self.at += 1;
            out |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(out);
            }
            shift += 7;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn field(number: u32, wire: u8, body: &[u8]) -> Vec<u8> {
        let mut out = varint(u64::from((number << 3) | u32::from(wire)));
        out.extend(body);
        out
    }

    fn len_field(number: u32, body: &[u8]) -> Vec<u8> {
        let mut out = field(number, 2, &varint(body.len() as u64));
        out.extend(body);
        out
    }

    fn site_bytes() -> Vec<u8> {
        let domain = {
            let mut body = field(1, 0, &varint(3));
            body.extend(len_field(2, b"Example.COM"));
            body
        };
        let entry = {
            let mut body = len_field(1, b"cn");
            body.extend(len_field(2, &domain));
            body
        };
        len_field(1, &entry)
    }

    fn ip_bytes() -> Vec<u8> {
        let cidr = {
            let mut body = len_field(1, &[203, 0, 113, 0]);
            body.extend(field(2, 0, &varint(24)));
            body
        };
        let entry = {
            let mut body = len_field(1, b"test");
            body.extend(len_field(2, &cidr));
            body
        };
        len_field(1, &entry)
    }

    #[test]
    fn geosite_full_and_geoip_prefix_match() {
        let dir = std::env::temp_dir().join(format!("kerlico-geo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::File::create(dir.join("geosite.dat"))
            .unwrap()
            .write_all(&site_bytes())
            .unwrap();
        std::fs::File::create(dir.join("geoip.dat"))
            .unwrap()
            .write_all(&ip_bytes())
            .unwrap();
        std::fs::write(dir.join("extra.dat"), site_bytes()).unwrap();
        let catalog = Catalog::load(&dir);
        assert!(catalog.site_hit("cn", "example.com"));
        assert!(!catalog.site_hit("cn", "www.example.com"));
        assert!(catalog.net_hit("test", IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
        assert!(!catalog.net_hit("test", IpAddr::V4(Ipv4Addr::new(203, 0, 114, 1))));
        assert!(catalog.ext_site("extra.dat", "cn", "example.com"));
        assert!(!catalog.has_net("private"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn runtime_catalog_preserves_family_presence_and_reuses_loaded_ext_file() {
        let dir = std::env::temp_dir().join(format!("kerlico-runtime-geo-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("geoip.dat"), ip_bytes()).unwrap();
        std::fs::write(dir.join("extra.dat"), ip_bytes()).unwrap();
        let catalog = Catalog::load(&dir);
        let native = catalog.network_set("geoip.dat", "TEST").unwrap();
        assert!(native.has_ipv4);
        assert!(!native.has_ipv6);
        assert!(native.contains("203.0.113.7".parse().unwrap()));
        assert!(!native.contains("2001:db8::7".parse().unwrap()));
        let external = catalog.network_set("extra.dat", "TEST").unwrap();
        std::fs::remove_file(dir.join("extra.dat")).unwrap();
        assert!(catalog.network_set("extra.dat", "test").unwrap().contains("203.0.113.7".parse().unwrap()));
        assert!(external.has_ipv4 && !external.has_ipv6);
        assert!(catalog.network_set("geoip.dat", "missing").is_err());
        std::fs::remove_file(dir.join("geoip.dat")).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
