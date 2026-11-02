use base64::{Engine as _, engine::general_purpose::STANDARD};
use kerlico_config::{Config, OutboundFactory, Registry};
use kerlico_core::{
    CancellationToken, ConnectContext, Destination, Error, Outbound, Result, ServiceContext,
};
use kerlico_wireguard::{WireGuardFactory, WireGuardNodeFactory};
use serde_json::{Value, json};
use std::{io::Write, sync::Arc, time::Duration};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, time::{Instant, timeout}};

fn emit(value: Value) { println!("{value}"); let _ = std::io::stdout().flush(); }
fn target(value: &Value) -> Result<Destination> {
    let host = value["host"].as_str().ok_or(Error::InvalidAddress)?;
    let port = u16::try_from(value["port"].as_u64().ok_or(Error::InvalidAddress)?).map_err(|_| Error::InvalidAddress)?;
    Destination::new(host, port)
}
fn decode(value: &Value) -> Result<Vec<u8>> {
    let value = value.as_str().ok_or(Error::Protocol("验证请求缺少Base64载荷"))?;
    if value.len() > 24 * 1024 * 1024 { return Err(Error::ResourceLimit); }
    STANDARD.decode(value).map_err(|_| Error::Protocol("验证请求Base64不合法"))
}
async fn call(outbound: &dyn Outbound, request: &Value) -> Result<Value> {
    let context = ConnectContext::new(Duration::from_secs(15));
    match request["op"].as_str() {
        Some("tcp") => {
            let target = target(&request["target"])?;
            let payload = decode(&request["payload"])?;
            let mut stream = outbound.connect_tcp(&target, &context).await?.stream;
            stream.write_all(&payload).await?;
            stream.shutdown().await?;
            let mut data = Vec::new();
            stream.take(16 * 1024 * 1024).read_to_end(&mut data).await?;
            Ok(json!({"ok": true, "payload": STANDARD.encode(data)}))
        }
        Some("fixed_udp") => {
            let target = target(&request["target"])?;
            let mut channel = outbound.connect_udp(&target, &context).await?;
            let mut replies = Vec::new();
            for payload in request["payloads"].as_array().ok_or(Error::Protocol("验证请求缺少数据报列表"))? {
                channel.sender.send(&decode(payload)?).await?;
                let data = channel.receiver.recv().await?.ok_or(Error::Protocol("验证UDP通道提前关闭"))?;
                replies.push(json!({"source": target.to_string(), "payload": STANDARD.encode(data)}));
            }
            Ok(json!({"ok": true, "packets": replies}))
        }
        Some("association_udp") => {
            let mut channel = outbound.associate_udp(&context).await?;
            let mut replies = Vec::new();
            for packet in request["packets"].as_array().ok_or(Error::Protocol("验证请求缺少目标数据报列表"))? {
                let target = target(&packet["target"])?;
                channel.sender.send_to(&decode(&packet["payload"])?, &target).await?;
                let (source, data) = channel.receiver.recv_from().await?.ok_or(Error::Protocol("验证UDP关联提前关闭"))?;
                replies.push(json!({"source": source.to_string(), "payload": STANDARD.encode(data)}));
            }
            for _ in 0..request["extra_receives"].as_u64().unwrap_or(0).min(8) {
                let (source, data) = channel.receiver.recv_from().await?.ok_or(Error::Protocol("验证UDP关联提前关闭"))?;
                replies.push(json!({"source": source.to_string(), "payload": STANDARD.encode(data)}));
            }
            Ok(json!({"ok": true, "packets": replies}))
        }
        _ => Err(Error::Protocol("未知验证操作")),
    }
}
async fn client(options: Value) -> Result<()> {
    let host = ServiceContext::for_test();
    let outbound: Arc<dyn Outbound> = WireGuardFactory.compile(&options)?.start(host.clone()).await?;
    emit(json!({"ready": true, "role": "client"}));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let request: Value = serde_json::from_str(&line).map_err(|_| Error::Protocol("验证请求JSON不合法"))?;
        if request["op"] == "stop" { break; }
        if request["op"] == "snapshot" {
            let carrier = host.carrier_usage();
            emit(json!({"ok":true, "carrier":{"sent_bytes":carrier.sent_bytes,"received_bytes":carrier.received_bytes,"saturated":carrier.saturated}}));
            continue;
        }
        let result = timeout(Duration::from_secs(30), call(&*outbound, &request)).await;
        emit(match result {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => json!({"ok": false, "error": error.to_string()}),
            Err(_) => json!({"ok": false, "error": "验证操作超时"}),
        });
    }
    let stopped = outbound.shutdown().await;
    let report = host.shutdown(Instant::now() + Duration::from_secs(3)).await;
    emit(json!({"stopped": true, "clean": stopped.is_ok() && report.is_clean()}));
    stopped
}
fn snapshot(telemetry: &kerlico_egress::Telemetry) -> Result<Value> {
    let usage = telemetry.usage()?;
    let records = telemetry.records(0, 4096)?.iter().map(|record| json!({
        "user": record.source.user().map(|id| id.to_string()), "node":record.source.node().as_str(),
        "original": record.original.as_ref().map(|target| target.target().to_string()),
        "kind":format!("{:?}", record.kind), "end":record.end.map(|end| format!("{end:?}")),
        "upload_bytes":record.usage.upload_bytes,"download_bytes":record.usage.download_bytes,
        "upload_packets":record.usage.upload_packets,"download_packets":record.usage.download_packets,
        "targets":record.datagram_targets.iter().map(|target| target.original.to_string()).collect::<Vec<_>>(),
    })).collect::<Vec<_>>();
    Ok(json!({"ok":true, "active_flows":usage.active_flows, "users":usage.users.len(),
        "upload_bytes":usage.engine.upload_bytes,"download_bytes":usage.engine.download_bytes,"records":records}))
}
async fn node(config: Value) -> Result<()> {
    let mut registry = Registry::default();
    registry.register(kerlico_net::DirectFactory)?;
    registry.register(WireGuardFactory)?;
    registry.register_node(WireGuardNodeFactory)?;
    let config: Config = serde_json::from_value(config).map_err(|_| Error::Config("验证节点配置不合法".into()))?;
    let engine = kerlico_engine::Engine::bind(registry.prepare(config)?).await?;
    let telemetry = engine.telemetry();
    let listeners = engine.listeners()?.iter().map(|(tag, address)| json!({"tag":tag,"address":address.to_string()})).collect::<Vec<_>>();
    let cancel = CancellationToken::new();
    let engine_cancel = cancel.clone();
    let run = tokio::spawn(async move { engine.run(engine_cancel).await });
    emit(json!({"ready":true,"role":"node","listeners":listeners}));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let request: Value = serde_json::from_str(&line).map_err(|_| Error::Protocol("验证请求JSON不合法"))?;
        match request["op"].as_str() {
            Some("snapshot") => emit(snapshot(&telemetry)?),
            Some("stop") => break,
            _ => emit(json!({"ok":false,"error":"未知验证节点操作"})),
        }
    }
    cancel.cancel();
    let result = timeout(Duration::from_secs(6), run).await.map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Protocol("验证Engine任务异常退出"))?;
    let final_snapshot = snapshot(&telemetry)?;
    emit(json!({"stopped":true,"clean":result.is_ok(),"snapshot":final_snapshot}));
    result
}
#[tokio::main]
async fn main() -> Result<()> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 3 { return Err(Error::Config("用法为wireguard-peer client或node 配置文件".into())); }
    let config: Value = serde_json::from_slice(&tokio::fs::read(&arguments[2]).await?)
        .map_err(|_| Error::Config("验证配置JSON不合法".into()))?;
    match arguments[1].as_str() { "client" => client(config).await, "node" => node(config).await,
        _ => Err(Error::Config("验证角色只能为client或node".into())) }
}
