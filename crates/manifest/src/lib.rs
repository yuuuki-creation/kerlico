//! Compares each leaf's optional dependencies with `protocols/`.
//! `Role` lives here so shared protocol code has no role enum.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }

    const fn other(self) -> &'static str {
        match self {
            Self::Client => "server",
            Self::Server => "client",
        }
    }

    fn feature_env(self, id: &str) -> String {
        let _ = self;
        format!("CARGO_FEATURE_{}", id.to_ascii_uppercase().replace('-', "_"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckFailure {
    pub detail: String,
}

impl CheckFailure {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// Fails when the leaf menu, the protocol directories, or a role crate disagree.
pub fn emit_leaf(role: Role, manifest: &Path, out_dir: &Path) -> Result<(), CheckFailure> {
    let repo = repo_root(manifest)?;
    let text = read(manifest)?;
    let menu = offers_from_manifest(&text, role)?;
    for id in &menu.landings {
        check_protocol(&repo, Role::Client, id)?;
    }
    let tree = offers_from_tree(&repo.join("protocols"), role)?;
    if menu.offers != tree {
        return Err(CheckFailure::new(format!(
            "{} menu [{joined}] does not match protocols/ [{dirs}]",
            role.dir_name(),
            joined = join_ids(&menu.offers),
            dirs = join_ids(&tree),
        )));
    }
    check_shared(&repo.join("crates/shared/Cargo.toml"))?;
    for id in &menu.offers {
        check_protocol(&repo, role, id)?;
    }
    let enabled: Vec<&str> = menu
        .offers
        .iter()
        .filter(|id| std::env::var_os(role.feature_env(id)).is_some())
        .map(String::as_str)
        .collect();
    let enabled_landings: Vec<&str> = menu
        .landings
        .iter()
        .filter(|id| std::env::var_os(role.feature_env(&format!("landing-{id}"))).is_some())
        .map(String::as_str)
        .collect();
    write_registry(role, out_dir, &enabled, &enabled_landings)?;
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed={}", repo.join("protocols").display());
    Ok(())
}

fn repo_root(manifest: &Path) -> Result<PathBuf, CheckFailure> {
    manifest
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| CheckFailure::new("leaf manifest is not crates/<role>/Cargo.toml"))
}

fn offers_from_tree(protocols: &Path, role: Role) -> Result<BTreeSet<String>, CheckFailure> {
    let mut offers = BTreeSet::new();
    let entries = fs::read_dir(protocols).map_err(|error| {
        CheckFailure::new(format!("read {}: {error}", protocols.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| CheckFailure::new(error.to_string()))?;
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        valid_id(&id)?;
        let shared = entry.path().join("shared/Cargo.toml");
        if !shared.is_file() {
            return Err(CheckFailure::new(format!(
                "protocols/{id}/shared/Cargo.toml is missing"
            )));
        }
        check_shared_protocol(&shared, &id)?;
        if entry.path().join(role.dir_name()).join("Cargo.toml").is_file() {
            offers.insert(id);
        }
    }
    Ok(offers)
}

struct Menu {
    offers: BTreeSet<String>,
    landings: BTreeSet<String>,
}

fn offers_from_manifest(toml: &str, role: Role) -> Result<Menu, CheckFailure> {
    if toml.lines().any(|line| line.trim() == "[features]") {
        return Err(CheckFailure::new(
            "a leaf has no [features] table. optional dependency keys are the protocol menu",
        ));
    }
    let mut in_dependencies = false;
    let mut offers = BTreeSet::new();
    let mut landings = BTreeSet::new();
    for line in toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dependencies = trimmed == "[dependencies]";
            continue;
        }
        if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.contains("protocols/") {
            continue;
        }
        let Some((key, rest)) = trimmed.split_once('=') else {
            return Err(CheckFailure::new(format!(
                "protocol dependency is not one assignment: {trimmed}"
            )));
        };
        let key = key.trim();
        if let Some(id) = key.strip_prefix("landing-") {
            if role != Role::Server {
                return Err(CheckFailure::new(
                    "landing- dependencies belong on the server leaf",
                ));
            }
            valid_id(id)?;
            if !rest.contains("optional = true") {
                return Err(CheckFailure::new(format!(
                    "{key} is a protocol dependency, so it is optional"
                )));
            }
            if rest.contains("dep:") {
                return Err(CheckFailure::new(format!(
                    "{key} uses dep:, which hides the implicit feature"
                )));
            }
            let package = format!("kerlico-{id}-client");
            let path = format!("../../protocols/{id}/client");
            if !rest.contains(&format!("package = \"{package}\"")) {
                return Err(CheckFailure::new(format!("{key} package is {package}")));
            }
            if !rest.contains(&format!("path = \"{path}\"")) {
                return Err(CheckFailure::new(format!("{key} path is {path}")));
            }
            landings.insert(id.to_string());
            continue;
        }
        valid_id(key)?;
        if !rest.contains("optional = true") {
            return Err(CheckFailure::new(format!(
                "{key} is a protocol dependency, so it is optional"
            )));
        }
        if rest.contains("dep:") {
            return Err(CheckFailure::new(format!(
                "{key} uses dep:, which hides the implicit feature"
            )));
        }
        let package = format!("kerlico-{key}-{}", role.dir_name());
        let path = format!("../../protocols/{key}/{}", role.dir_name());
        if !rest.contains(&format!("package = \"{package}\"")) {
            return Err(CheckFailure::new(format!(
                "{key} package is {package}"
            )));
        }
        if !rest.contains(&format!("path = \"{path}\"")) {
            return Err(CheckFailure::new(format!("{key} path is {path}")));
        }
        if rest.contains(&format!("-{}", role.other())) {
            return Err(CheckFailure::new(format!(
                "{} leaf names a {} crate",
                role.dir_name(),
                role.other()
            )));
        }
        offers.insert(key.to_string());
    }
    Ok(Menu { offers, landings })
}

fn check_shared(manifest: &Path) -> Result<(), CheckFailure> {
    let text = read(manifest)?;
    if text.lines().any(|line| line.trim() == "[features]") {
        return Err(CheckFailure::new(
            "kerlico-shared has no [features] table",
        ));
    }
    if text.contains("protocols/") || text.contains("-client") || text.contains("-server") {
        return Err(CheckFailure::new(
            "kerlico-shared does not depend on a role crate",
        ));
    }
    Ok(())
}

fn check_shared_protocol(manifest: &Path, id: &str) -> Result<(), CheckFailure> {
    let text = read(manifest)?;
    if text.lines().any(|line| line.trim() == "[features]") {
        return Err(CheckFailure::new(format!(
            "protocols/{id}/shared has no [features] table"
        )));
    }
    if !text.contains(&format!("name = \"kerlico-{id}\"")) {
        return Err(CheckFailure::new(format!(
            "protocols/{id}/shared package name is kerlico-{id}"
        )));
    }
    if text.contains("-client") || text.contains("-server") || text.contains("protocols/") {
        return Err(CheckFailure::new(format!(
            "protocols/{id}/shared does not depend on a role crate"
        )));
    }
    Ok(())
}

fn check_protocol(repo: &Path, role: Role, id: &str) -> Result<(), CheckFailure> {
    let crate_dir = repo.join("protocols").join(id).join(role.dir_name());
    let manifest = crate_dir.join("Cargo.toml");
    let text = read(&manifest)?;
    let package = format!("kerlico-{id}-{}", role.dir_name());
    if !text.contains(&format!("name = \"{package}\"")) {
        return Err(CheckFailure::new(format!(
            "{package} package name does not match the directory"
        )));
    }
    if !text.contains("path = \"../shared\"") {
        return Err(CheckFailure::new(format!(
            "{package} depends on ../shared"
        )));
    }
    if !text.contains("path = \"../../../crates/shared\"") {
        return Err(CheckFailure::new(format!(
            "{package} depends on kerlico-shared"
        )));
    }
    if text.contains(&format!("-{}", role.other())) || text.contains(&format!("/{}/", role.other()))
    {
        return Err(CheckFailure::new(format!(
            "{package} depends on the {} role",
            role.other()
        )));
    }
    let source = crate_dir.join("src");
    if source.is_dir() {
        scan_source(&source)?;
    }
    Ok(())
}

fn scan_source(dir: &Path) -> Result<(), CheckFailure> {
    let entries = fs::read_dir(dir).map_err(|error| CheckFailure::new(error.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|error| CheckFailure::new(error.to_string()))?;
        let path = entry.path();
        if path.is_dir() {
            scan_source(&path)?;
            continue;
        }
        let text = read(&path)?;
        if text.contains("PROTOCOL_ID") {
            return Err(CheckFailure::new(format!(
                "{} defines PROTOCOL_ID. The directory name is the id",
                path.display()
            )));
        }
    }
    Ok(())
}

fn valid_id(id: &str) -> Result<(), CheckFailure> {
    let bytes = id.as_bytes();
    if bytes.is_empty() {
        return Err(CheckFailure::new("protocol id is empty"));
    }
    let mut segment = 0;
    for byte in bytes {
        if *byte == b'-' {
            if segment == 0 {
                return Err(CheckFailure::new(format!("protocol id {id} has an empty segment")));
            }
            segment = 0;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            segment += 1;
        } else {
            return Err(CheckFailure::new(format!(
                "protocol id {id} is lowercase letters, digits, and single hyphens"
            )));
        }
    }
    if segment == 0 {
        return Err(CheckFailure::new(format!("protocol id {id} ends with a hyphen")));
    }
    Ok(())
}

fn write_registry(
    role: Role,
    out_dir: &Path,
    enabled: &[&str],
    landings: &[&str],
) -> Result<(), CheckFailure> {
    let mut body = String::new();
    match role {
        Role::Client => body.push_str(
            "use kerlico_shared::{ClientEntry, ProtocolId};\n#[allow(dead_code)]\npub(super) struct Registration { pub(super) id: ProtocolId, pub(super) entry: ClientEntry }\n",
        ),
        Role::Server => body.push_str(
            "use kerlico_shared::{OpenError, ProtocolId, Settings};\nuse kerlico_shared::{Accept, Destination, InboundStream, ListenAddr, NodeTag};\n#[allow(dead_code)]\npub(super) type ListenFn = fn(&NodeTag, &ListenAddr, &Settings) -> Result<Box<dyn Accept>, OpenError>;\n#[allow(dead_code)]\npub(super) struct Registration { pub(super) id: ProtocolId, pub(super) listen: ListenFn }\n#[allow(dead_code)]\npub(super) type LandFn = fn(&str, u16, &Settings, &Destination) -> Result<Box<dyn InboundStream>, OpenError>;\n#[allow(dead_code)]\npub(super) struct LandRegistration { pub(super) id: ProtocolId, pub(super) land: LandFn }\n",
        ),
    }
    body.push_str("pub(super) static REGISTRY: &[Registration] = &[\n");
    for id in enabled {
        let rust_name = id.replace('-', "_");
        match role {
            Role::Client => body.push_str(&format!(
                "    Registration {{ id: ProtocolId::must(\"{id}\"), entry: {rust_name}::CLIENT }},\n"
            )),
            Role::Server => body.push_str(&format!(
                "    Registration {{ id: ProtocolId::must(\"{id}\"), listen: {rust_name}::listen }},\n"
            )),
        }
    }
    body.push_str("];\n");
    if role == Role::Server {
        body.push_str("pub(super) static LANDINGS: &[LandRegistration] = &[\n");
        for id in landings {
            let rust_name = format!("landing_{}", id.replace('-', "_"));
            body.push_str(&format!(
                "    LandRegistration {{ id: ProtocolId::must(\"{id}\"), land: {rust_name}::land }},\n"
            ));
        }
        body.push_str("];\n");
    }
    body.push_str("pub(super) static COMPILED: &[ProtocolId] = &[\n");
    for id in enabled {
        body.push_str(&format!("    ProtocolId::must(\"{id}\"),\n"));
    }
    body.push_str("];\n");
    let path = out_dir.join("registry.rs");
    fs::write(&path, body).map_err(|error| CheckFailure::new(format!("write {}: {error}", path.display())))
}

fn join_ids(ids: &BTreeSet<String>) -> String {
    ids.iter().cloned().collect::<Vec<_>>().join(", ")
}

fn read(path: &Path) -> Result<String, CheckFailure> {
    fs::read_to_string(path).map_err(|error| CheckFailure::new(format!("read {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_tree_matches_both_leaves() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let client = fs::read_to_string(repo.join("crates/client/Cargo.toml")).unwrap();
        let server = fs::read_to_string(repo.join("crates/server/Cargo.toml")).unwrap();
        emit_leaf(Role::Client, &repo.join("crates/client/Cargo.toml"), &std::env::temp_dir())
            .expect("client menu");
        emit_leaf(Role::Server, &repo.join("crates/server/Cargo.toml"), &std::env::temp_dir())
            .expect("server menu");
        let _ = (client, server);
    }

    #[test]
    fn missing_client_key_names_the_directory() {
        let dir = std::env::temp_dir().join(format!("kerlico-menu-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("protocols/wireguard/shared")).unwrap();
        fs::create_dir_all(dir.join("protocols/wireguard/client")).unwrap();
        fs::write(
            dir.join("protocols/wireguard/shared/Cargo.toml"),
            "[package]\nname = \"kerlico-wireguard\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            dir.join("protocols/wireguard/client/Cargo.toml"),
            "[package]\nname = \"kerlico-wireguard-client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("crates/client")).unwrap();
        let manifest = dir.join("crates/client/Cargo.toml");
        fs::write(
            &manifest,
            "[dependencies]\nkerlico-shared = { path = \"../shared\" }\n",
        )
        .unwrap();
        let error = emit_leaf(Role::Client, &manifest, &dir).unwrap_err();
        assert!(
            error.detail.contains("wireguard"),
            "{}",
            error.detail
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn server_leaf_accepts_a_landing_client_crate() {
        let dir = std::env::temp_dir().join(format!("kerlico-landing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("protocols/wireguard/shared/src")).unwrap();
        fs::create_dir_all(dir.join("protocols/wireguard/server/src")).unwrap();
        fs::create_dir_all(dir.join("protocols/wireguard/client/src")).unwrap();
        fs::create_dir_all(dir.join("crates/shared")).unwrap();
        fs::create_dir_all(dir.join("crates/server")).unwrap();
        fs::write(
            dir.join("crates/shared/Cargo.toml"),
            "[package]\nname = \"kerlico-shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            dir.join("protocols/wireguard/shared/Cargo.toml"),
            "[package]\nname = \"kerlico-wireguard\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let role = "[dependencies]\nkerlico-wireguard = { path = \"../shared\" }\nkerlico-shared = { path = \"../../../crates/shared\" }\n";
        fs::write(
            dir.join("protocols/wireguard/server/Cargo.toml"),
            format!("[package]\nname = \"kerlico-wireguard-server\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n{role}"),
        )
        .unwrap();
        fs::write(
            dir.join("protocols/wireguard/client/Cargo.toml"),
            format!("[package]\nname = \"kerlico-wireguard-client\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n{role}"),
        )
        .unwrap();
        let manifest = dir.join("crates/server/Cargo.toml");
        fs::write(
            &manifest,
            "[dependencies]\nwireguard = { package = \"kerlico-wireguard-server\", path = \"../../protocols/wireguard/server\", optional = true }\nlanding-wireguard = { package = \"kerlico-wireguard-client\", path = \"../../protocols/wireguard/client\", optional = true }\n",
        )
        .unwrap();
        emit_leaf(Role::Server, &manifest, &dir).expect("landing key");
        let registry = fs::read_to_string(dir.join("registry.rs")).unwrap();
        assert!(!registry.contains("landing"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
