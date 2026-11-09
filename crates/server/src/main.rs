fn main() {
    let path = match std::env::args().nth(1) {
        Some(path) => path,
        None => {
            for id in kerlico_server::Server::compiled() {
                println!("{id}");
            }
            return;
        }
    };
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        eprintln!("{error}");
        String::new()
    });
    let dir = std::path::Path::new(&path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut loaded = kerlico_server::Server::from_config_in(&text, dir).unwrap_or_else(|_| {
        eprintln!("config");
        std::process::exit(1);
    });
    for id in kerlico_server::Server::compiled() {
        println!("{id}");
    }
    if let Err(error) = loaded.server.run(loaded.dns) {
        eprintln!("{error:?}");
        std::process::exit(1);
    }
}
