mod common;

use common::*;
use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, Error};
use kerlico_sudoku::SudokuFactory;
use serde_json::json;
use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, timeout},
};

// 保留原8秒、负载和write_all/flush/FIN顺序，只记录超时时停在哪一步。
async fn mux_exchange(
    mode: &str,
    outbound: &Arc<dyn kerlico_core::Outbound>,
    target: &Destination,
    bytes: Vec<u8>,
    state: &Arc<State>,
) {
    let context = ConnectContext::new(WAIT);
    let mut stream = outbound.connect_tcp(target, &context).await.unwrap();
    banner(&mut stream).await;
    let eof = outbound.capabilities().tcp_eof;
    let sent = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(AtomicUsize::new(0));
    let tail_bytes = Arc::new(AtomicUsize::new(0));
    let samples = Arc::new(Mutex::new(Vec::new()));
    let sample_state = state.clone();
    let sample_sent = sent.clone();
    let sample_received = received.clone();
    let sample_tail = tail_bytes.clone();
    let sample_output = samples.clone();
    let port = target.port();
    struct SamplingTask(tokio::task::JoinHandle<()>);
    impl Drop for SamplingTask { fn drop(&mut self) { self.0.abort(); } }
    // 独立任务只读原子计数，既不poll传输future，也不给它添加定时唤醒。
    let sampler = SamplingTask(tokio::spawn(async move {
        let start = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        for _ in 0..9 {
            tick.tick().await;
            let sample = format!("t={}ms send={} received={} tail={} target={:?}",start.elapsed().as_millis(),sample_sent.load(Ordering::SeqCst),sample_received.load(Ordering::SeqCst),sample_tail.load(Ordering::SeqCst),sample_state.target_snapshot(port));
            sample_output.lock().unwrap().push(sample);
        }
    }));
    let (mut read, mut write) = tokio::io::split(stream);
    let sending = async {
        write.write_all(&bytes).await.unwrap();
        sent.store(1, Ordering::SeqCst);
        write.flush().await.unwrap();
        sent.store(2, Ordering::SeqCst);
        if eof {
            write.shutdown().await.unwrap();
        }
        sent.store(3, Ordering::SeqCst);
    };
    let receiving = async {
        let mut data = vec![0; bytes.len()];
        let mut used = 0;
        while used < data.len() {
            let count = read.read(&mut data[used..]).await.unwrap();
            assert!(count != 0, "mux提前EOF: mode={mode} target={target} used={used}");
            used += count;
            received.store(used, Ordering::SeqCst);
        }
        assert_eq!(data, bytes);
        if eof {
            let mut tail = Vec::new();
            let mut piece = [0; 32];
            loop {
                let count = read.read(&mut piece).await.unwrap();
                if count == 0 { break; }
                tail.extend_from_slice(&piece[..count]);
                tail_bytes.store(tail.len(), Ordering::SeqCst);
            }
            assert_eq!(tail, TAIL);
        }
    };
    let result = timeout(WAIT, async { tokio::join!(sending, receiving); }).await;
    drop(sampler);
    assert!(result.is_ok(), "mux超时: mode={mode} target={target} bytes={} send_stage={} (0=write_all,1=flush,2=FIN,3=done) received={} tail={} target_progress={:?} samples={:?}", bytes.len(), sent.load(Ordering::SeqCst), received.load(Ordering::SeqCst), tail_bytes.load(Ordering::SeqCst),state.target_snapshot(target.port()),samples.lock().unwrap());
}

#[tokio::test]
async fn real_mux_uses_one_carrier_for_concurrent_distinct_targets_and_fin() {
    for mode in ["raw", "legacy", "stream", "poll", "auto", "ws"] {
        let fixture = Fixture::start(mode, "chacha20-poly1305", "on", false).await;
        let context = ConnectContext::new(WAIT);
        let first = Destination::new("127.0.0.1", 10000).unwrap();
        let mut held = fixture
            .outbound
            .connect_tcp(&first, &context)
            .await
            .unwrap();
        banner(&mut held).await;
        let physical = fixture.state.physical.load(Ordering::SeqCst);
        assert!(physical > 0);
        let mut jobs = tokio::task::JoinSet::new();
        for index in 0..16 {
            let outbound = fixture.outbound.clone();
            let state = fixture.state.clone();
            jobs.spawn(async move {
                let target = Destination::new(
                    if index % 2 == 0 { "127.0.0.1" } else { "::1" },
                    10001 + index,
                )
                .unwrap();
                mux_exchange(
                    mode,
                    &outbound,
                    &target,
                    vec![index as u8; 65536 + usize::from(index)],
                    &state,
                )
                .await;
            });
        }
        while let Some(result) = jobs.join_next().await {
            result.unwrap();
        }
        assert_eq!(
            fixture.state.physical.load(Ordering::SeqCst),
            physical,
            "逻辑流不得另拨载体: {mode}"
        );
        let decoded = fixture.state.decoded.lock().unwrap().clone();
        for port in 10000..10017 {
            assert!(decoded.iter().any(|t| t.port() == port));
        }
        held.shutdown().await.unwrap();
        let mut tail = Vec::new();
        timeout(WAIT, held.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, TAIL);
        drop(held);
        fixture.close().await;
    }
}

#[tokio::test]
async fn logical_cancel_reset_and_target_rejection_leave_siblings_alive() {
    for mode in ["raw", "stream", "poll", "ws"] {
        let fixture = Fixture::start(mode, "aes-128-gcm", "on", false).await;
        let cancel_context = ConnectContext::new(WAIT);
        let target = Destination::new("127.0.0.1", 443).unwrap();
        let mut victim = fixture
            .outbound
            .connect_tcp(&target, &cancel_context)
            .await
            .unwrap();
        banner(&mut victim).await;
        let context = ConnectContext::new(WAIT);
        let mut survivor = fixture
            .outbound
            .connect_tcp(&target, &context)
            .await
            .unwrap();
        banner(&mut survivor).await;
        let physical = fixture.state.physical.load(Ordering::SeqCst);
        cancel_context.cancel.cancel();
        let mut byte = [0; 1];
        assert!(!matches!(
            timeout(WAIT, victim.read(&mut byte)).await,
            Ok(Ok(1))
        ));
        drop(victim);
        let rejected = Destination::new("127.0.0.1", 1).unwrap();
        match fixture.outbound.connect_tcp(&rejected, &context).await {
            Ok(mut stream) => {
                assert!(!matches!(
                    timeout(WAIT, stream.read(&mut byte)).await,
                    Ok(Ok(1))
                ));
            }
            Err(Error::Rejected | Error::Io(_) | Error::Cancelled) => {}
            Err(error) => panic!("未预期目标拒绝错误: {error}"),
        }
        survivor.write_all(b"still-alive").await.unwrap();
        survivor.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        timeout(WAIT, survivor.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, b"still-alivetail");
        exchange(&fixture.outbound, &target, vec![8; 1024]).await;
        assert_eq!(fixture.state.physical.load(Ordering::SeqCst), physical);
        drop(survivor);
        fixture.close().await;
    }
}

#[tokio::test]
async fn slow_stream_backpressure_does_not_block_another_stream() {
    let fixture = Fixture::start("raw", "chacha20-poly1305", "on", false).await;
    let context = ConnectContext::new(WAIT);
    let slow_target = Destination::new("127.0.0.1", 9).unwrap();
    let mut slow = fixture
        .outbound
        .connect_tcp(&slow_target, &context)
        .await
        .unwrap();
    banner(&mut slow).await;
    let filling = tokio::spawn(async move {
        let data = vec![0x33; 6 * 1024 * 1024];
        let result = slow.write_all(&data).await;
        (slow, result)
    });
    mux_exchange(
        "raw/slow-active",
        &fixture.outbound,
        &Destination::new("127.0.0.1", 443).unwrap(),
        vec![0x91; 16384],
        &fixture.state,
    )
    .await;
    context.cancel.cancel();
    let (stream, _) = timeout(WAIT, filling).await.unwrap().unwrap();
    drop(stream);
    assert_eq!(fixture.state.physical.load(Ordering::SeqCst), 1);
    mux_exchange(
        "raw/slow-cancelled",
        &fixture.outbound,
        &Destination::new("::1", 8443).unwrap(),
        vec![0x62; 16384],
        &fixture.state,
    )
    .await;
    fixture.close().await;
}

#[tokio::test]
async fn mux_pool_limits_released_slots_and_idle_carrier_replacement() {
    let state = Arc::new(State::default());
    let mut node = node_options("raw", KEY, "aes-128-gcm");
    node["max_mux_streams"] = json!(2);
    let server = Running::start(configuration(node, false, false), state.clone()).await;
    let mut options = client_options(server.addresses["node"], "raw", KEY, "aes-128-gcm", "on");
    options["max_mux_streams"] = json!(2);
    options["max_pool_sessions"] = json!(1);
    options["pool_idle_ms"] = json!(100);
    let outbound = SudokuFactory.build(&options).unwrap();
    let context = ConnectContext::new(WAIT);
    let target = Destination::new("127.0.0.1", 443).unwrap();
    let mut first = outbound.connect_tcp(&target, &context).await.unwrap();
    banner(&mut first).await;
    let mut second = outbound.connect_tcp(&target, &context).await.unwrap();
    banner(&mut second).await;
    assert!(matches!(
        outbound.connect_tcp(&target, &context).await,
        Err(Error::ResourceLimit)
    ));
    drop(first);
    eventually(|| state.active_tcp.load(Ordering::SeqCst) == 1).await;
    exchange(&outbound, &target, vec![0x21; 1024]).await;
    drop(second);
    eventually(|| state.active_tcp.load(Ordering::SeqCst) == 0).await;
    // 显式等待所测的空闲预算，不以延迟掩盖握手或业务时序错误。
    tokio::time::sleep(Duration::from_millis(250)).await;
    exchange(&outbound, &target, vec![0x22; 1024]).await;
    assert_eq!(state.physical.load(Ordering::SeqCst), 2);
    drop(outbound);
    server.close().await;
}

#[tokio::test]
async fn server_logical_budget_recovers_after_cancel_and_client_drop() {
    let state = Arc::new(State::default());
    let mut value = configuration(node_options("raw", KEY, "chacha20-poly1305"), false, false);
    value["limits"]["max_sessions"] = json!(6);
    value["nodes"][0]["max_sessions"] = json!(6);
    let server = Running::start(value, state.clone()).await;
    let outbound = SudokuFactory
        .build(&client_options(
            server.addresses["node"],
            "raw",
            KEY,
            "chacha20-poly1305",
            "on",
        ))
        .unwrap();
    let context = ConnectContext::new(WAIT);
    let target = Destination::new("127.0.0.1", 443).unwrap();
    let mut streams = Vec::new();
    for _ in 0..5 {
        let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
        banner(&mut stream).await;
        streams.push(stream);
    }
    let budget = state.budgets.lock().unwrap()[0].clone();
    assert!(matches!(budget.try_acquire(), Err(Error::ResourceLimit)));
    context.cancel.cancel();
    drop(streams);
    eventually(|| state.active_tcp.load(Ordering::SeqCst) == 0).await;
    eventually(|| {
        let leases: Vec<_> = (0..5).filter_map(|_| budget.try_acquire().ok()).collect();
        leases.len() == 5
    })
    .await;
    let new_context = ConnectContext::new(WAIT);
    let mut live = outbound.connect_tcp(&target, &new_context).await.unwrap();
    banner(&mut live).await;
    drop(outbound);
    let mut byte = [0; 1];
    assert!(!matches!(
        timeout(WAIT, live.read(&mut byte)).await,
        Ok(Ok(1))
    ));
    drop(live);
    eventually(|| state.active_tcp.load(Ordering::SeqCst) == 0).await;
    eventually(|| {
        let leases: Vec<_> = (0..6).filter_map(|_| budget.try_acquire().ok()).collect();
        leases.len() == 6
    })
    .await;
    server.close().await;
}

#[tokio::test]
async fn root_shutdown_terminates_mux_uot_and_releases_backend_tasks() {
    for mode in ["raw", "stream", "poll", "ws"] {
        let fixture = Fixture::start(mode, "chacha20-poly1305", "on", false).await;
        let context = ConnectContext::new(WAIT);
        let target = Destination::new("127.0.0.1", 443).unwrap();
        let mut tcp = fixture
            .outbound
            .connect_tcp(&target, &context)
            .await
            .unwrap();
        banner(&mut tcp).await;
        let mut udp = fixture.outbound.associate_udp(&context).await.unwrap();
        udp.sender.send_to(b"before-stop", &target).await.unwrap();
        assert!(
            timeout(WAIT, udp.receiver.recv_from())
                .await
                .unwrap()
                .unwrap()
                .is_some()
        );
        fixture.server.stop.cancel();
        let mut bytes = Vec::new();
        let _ = timeout(WAIT, tcp.read_to_end(&mut bytes)).await.unwrap();
        let result = timeout(WAIT, udp.receiver.recv_from()).await.unwrap();
        assert!(result.is_err() || result.unwrap().is_none());
        drop(tcp);
        drop(udp);
        fixture.close().await;
    }
}
