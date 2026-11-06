//! 真实 MetaCubeX 数据的加载耗时、内存与匹配耗时。设置 `KERLICO_GEO_ASSETS` 指向含
//! `geosite.dat`、`geoip.dat`、`country.mmdb`、`geosite-cn.mrs`、`geosite-cn.srs` 的目录时运行，
//! 否则跳过（大文件不入库）。

use kerlico_routing::{
    Behavior, CompiledRuleSet, GeoFile, GeoIpMode, GeoIpRef, GeoNeeds, GeoSiteRef, GeoSlot,
    MihomoFormat, Network, RuleSetFormat, SingBoxFormat,
};
use std::{path::PathBuf, time::Instant};

fn assets() -> Option<PathBuf> {
    std::env::var_os("KERLICO_GEO_ASSETS").map(PathBuf::from)
}

fn hosts() -> Vec<String> {
    (0..50_000)
        .map(|i| match i % 4 {
            0 => format!("img{i}.www.baidu.com"),
            1 => format!("cdn{i}.static.example{}.com", i % 211),
            2 => format!("a{i}.b.c.qq.com"),
            _ => format!("x{i}.googleusercontent.com"),
        })
        .collect()
}

#[test]
fn real_geosite_cn_loads_compact_and_matches_fast() {
    let Some(dir) = assets() else {
        eprintln!("跳过：未设置 KERLICO_GEO_ASSETS");
        return;
    };
    let mut needs = GeoNeeds::default();
    let cn = GeoSiteRef::parse("cn").unwrap();
    needs.add_site(&cn);
    needs.add_site(&GeoSiteRef::parse("geolocation-!cn").unwrap());
    let slot = GeoSlot::new(GeoIpMode::Mmdb, needs);
    let bytes = std::fs::read(dir.join("geosite.dat")).unwrap();
    let started = Instant::now();
    slot.install(slot.compile(GeoFile::GeoSite, &bytes).unwrap());
    let load = started.elapsed();
    let data = slot.load();
    let hosts = hosts();
    let started = Instant::now();
    let hits = hosts.iter().filter(|h| data.site_matches(&cn, h)).count();
    let per_match = started.elapsed() / u32::try_from(hosts.len()).unwrap();
    eprintln!(
        "geosite.dat cn+geolocation-!cn: load {load:?}, heap {} KiB, {per_match:?}/match, hits {hits}",
        data.heap_bytes() / 1024
    );
    assert!(data.site_matches(&cn, "www.baidu.com"));
    assert!(!data.site_matches(&cn, "www.google.com"));
    assert!(load.as_secs() < 5);
}

#[test]
fn real_mrs_and_srs_rule_sets_decode() {
    let Some(dir) = assets() else {
        eprintln!("跳过：未设置 KERLICO_GEO_ASSETS");
        return;
    };
    let hosts = hosts();
    for (name, format) in [
        (
            "geosite-cn.mrs",
            RuleSetFormat::Mihomo {
                behavior: Behavior::Domain,
                format: MihomoFormat::Mrs,
            },
        ),
        (
            "geosite-cn.srs",
            RuleSetFormat::SingBox(SingBoxFormat::Binary),
        ),
    ] {
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let started = Instant::now();
        let set = CompiledRuleSet {
            tag: name.into(),
            rules: format.decode(&bytes).unwrap(),
        };
        let load = started.elapsed();
        let started = Instant::now();
        let hits = hosts
            .iter()
            .filter(|h| set.matches(&[h.as_str()], &[], 443, Network::Tcp, None))
            .count();
        let per_match = started.elapsed() / u32::try_from(hosts.len()).unwrap();
        let heap: usize = set.rules.iter().map(|r| r.domains.heap_bytes()).sum();
        eprintln!(
            "{name}: {} entries, load {load:?}, heap {} KiB, {per_match:?}/match, hits {hits}",
            set.entry_count(),
            heap / 1024
        );
        assert!(set.entry_count() > 50_000);
        assert!(set.matches(&["www.baidu.com"], &[], 443, Network::Tcp, None));
    }
}

#[test]
fn real_country_mmdb_and_geoip_dat_lookups() {
    let Some(dir) = assets() else {
        eprintln!("跳过：未设置 KERLICO_GEO_ASSETS");
        return;
    };
    let cn = GeoIpRef::parse("cn").unwrap();
    let private = GeoIpRef::parse("private").unwrap();
    for (mode, file, name) in [
        (GeoIpMode::Mmdb, GeoFile::Mmdb, "country.mmdb"),
        (GeoIpMode::Dat, GeoFile::GeoIp, "geoip.dat"),
    ] {
        let mut needs = GeoNeeds::default();
        needs.add_ip(&cn);
        needs.add_ip(&private);
        let slot = GeoSlot::new(mode, needs);
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let started = Instant::now();
        slot.install(slot.compile(file, &bytes).unwrap());
        let load = started.elapsed();
        let data = slot.load();
        let ips: Vec<std::net::IpAddr> = (0..50_000u32)
            .map(|i| std::net::IpAddr::from((i.wrapping_mul(2_654_435_761)).to_be_bytes()))
            .collect();
        let started = Instant::now();
        let hits = ips.iter().filter(|ip| data.ip_matches(&cn, **ip)).count();
        let per_match = started.elapsed() / u32::try_from(ips.len()).unwrap();
        eprintln!(
            "{name}: load {load:?}, heap {} KiB, {per_match:?}/lookup, hits {hits}",
            data.heap_bytes() / 1024
        );
        assert!(data.ip_matches(&cn, "114.114.114.114".parse().unwrap()));
        assert!(!data.ip_matches(&cn, "8.8.8.8".parse().unwrap()));
        assert!(data.ip_matches(&private, "10.0.0.1".parse().unwrap()));
        assert!(!data.ip_matches(&private, "8.8.8.8".parse().unwrap()));
    }
}
