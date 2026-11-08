fn main() {
    let path = std::env::args().nth(1);
    let text = match path {
        Some(path) => std::fs::read_to_string(path).unwrap_or_default(),
        None => String::new(),
    };
    let _ = kerlico_client::ClientConfig::parse(&text);
    for id in kerlico_client::Client::compiled() {
        println!("{id}");
    }
}
