fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next();
    if path.as_deref() == Some("--mieru-proxy") {
        let Some(path) = args.next().filter(|_| args.next().is_none()) else {
            eprintln!("用法：kerlico-client --mieru-proxy <配置文件>");
            std::process::exit(1);
        };
        run_mieru(&path);
        return;
    }
    if path.is_none() {
        for id in kerlico_client::Client::compiled() {
            println!("{id}");
        }
        return;
    }
    let text = match path {
        Some(path) => std::fs::read_to_string(path).unwrap_or_default(),
        None => String::new(),
    };
    let _ = kerlico_client::ClientConfig::parse(&text);
    for id in kerlico_client::Client::compiled() {
        println!("{id}");
    }
}

#[cfg(feature = "mieru")]
fn run_mieru(path: &str) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|_| {
        eprintln!("无法读取 mieru 配置文件");
        std::process::exit(1);
    });
    if let Err(error) = mieru::run_proxy(&text) {
        eprintln!("mieru 启动或运行失败：{error:?}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "mieru"))]
fn run_mieru(_path: &str) {
    eprintln!("当前构建未包含 mieru 客户端");
    std::process::exit(1);
}
