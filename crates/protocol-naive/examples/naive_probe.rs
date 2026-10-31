//! 专用worker的公开API探针；不会作为kerlico产品载体或后台服务启动。
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, DatagramAssociation, Destination, Error, Result};
use kerlico_naive::NaiveFactory;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
#[derive(Deserialize)]
struct Command {
    network: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    payload: String,
    #[serde(default)]
    association: String,
    #[serde(default)]
    read_len: usize,
    #[serde(default)]
    shutdown: bool,
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    if std::env::var("KERLICO_WORKER_ONLY").as_deref() != Ok("1") {
        return Err("只允许在专用worker执行".into());
    }
    let path = std::env::args().nth(1).ok_or("缺少探针配置")?;
    let options: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let outbound = NaiveFactory.build(&options)?;
    let context = ConnectContext::new(Duration::from_secs(8));
    let mut associations = HashMap::<String, DatagramAssociation>::new();
    let mut input = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut output = tokio::io::stdout();
    while let Some(line) = input.next_line().await? {
        if line.len() > 4 * 1024 * 1024 {
            return Err("探针命令超限".into());
        }
        let result:Result<Value>=async {
            let command:Command=serde_json::from_str(&line).map_err(|_|Error::Protocol("探针命令不合法"))?;let payload=STANDARD.decode(command.payload).map_err(|_|Error::Protocol("探针字节编码不合法"))?;
            if command.network=="tcp"{if command.read_len>2*1024*1024{return Err(Error::ResourceLimit);}let target=Destination::new(&command.host,command.port)?;let mut stream=outbound.connect_tcp(&target,&context).await?;stream.write_all(&payload).await?;if command.shutdown{stream.shutdown().await?;}else{stream.flush().await?;}let mut bytes=vec![0;command.read_len];context.run(async {stream.read_exact(&mut bytes).await?;Ok(())}).await?;return Ok(json!({"ok":true,"payload":STANDARD.encode(bytes)}));}
            if !matches!(command.network.as_str(),"udp"|"udp-receive"){return Err(Error::Protocol("探针业务类型不合法"));}
            let key=if command.association.is_empty(){"default".into()}else{command.association};
            if !associations.contains_key(&key){associations.insert(key.clone(),outbound.associate_udp(&context).await?);}
            let association=associations.get_mut(&key).ok_or(Error::Rejected)?;
            if command.network=="udp" {let target=Destination::new(&command.host,command.port)?;context.run(association.sender.send_to(&payload,&target)).await?;}
            let (source,packet)=context.run(association.receiver.recv_from()).await?.ok_or(Error::Rejected)?;Ok(json!({"ok":true,"payload":STANDARD.encode(packet),"host":source.host(),"port":source.port()}))
        }.await;
        let response = match result {
            Ok(value) => value,
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        };
        output
            .write_all(serde_json::to_string(&response)?.as_bytes())
            .await?;
        output.write_all(b"\n").await?;
        output.flush().await?;
    }
    Ok(())
}
