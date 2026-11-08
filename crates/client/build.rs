fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.toml");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    if let Err(error) = kerlico_manifest::emit_leaf(kerlico_manifest::Role::Client, &manifest, &out) {
        panic!("{}", error.detail);
    }
}
