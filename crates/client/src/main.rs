use kerlico_client::{Client, ClientConfig, Error, Running};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (path, pinned) = match args.as_slice() {
        [] => {
            for id in Client::compiled() {
                println!("{id}");
            }
            return;
        }
        // Kept so mieru documents and tools/verify_mieru.py keep their command line.
        [flag, path] if flag == "--mieru-proxy" => (path, Some("mieru")),
        [path] if !path.starts_with("--") => (path, None),
        _ => fail("用法：kerlico-client [--mieru-proxy] <配置文件>"),
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        fail("无法读取配置文件");
    };
    let config = match ClientConfig::parse(&text, pinned) {
        Ok(config) => config,
        Err(Error::NotCompiled(id)) => fail(&format!("当前构建未包含 {id} 客户端")),
        Err(_) => fail("配置无效"),
    };
    let id = config.id();
    match Client::start(config) {
        Ok(Running::Proxy(proxy)) => {
            if proxy.wait().is_err() {
                fail(&format!("{id} 本机入口运行失败"));
            }
        }
        Ok(Running::Tunnel(_)) => fail(&format!("{id} 是隧道协议，命令行没有本机入口")),
        Err(error) => fail(&format!("{id} 启动失败：{error:?}")),
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
