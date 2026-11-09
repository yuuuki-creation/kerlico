use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mlua::{
    ChunkMode, Function, HookTriggers, Lua, LuaOptions, MultiValue, StdLib, String as LuaString,
    Table, UserData, UserDataMethods, Value, VmState,
};

use super::{random_bytes, VALUE_LIMIT};
use crate::finalmask::{invalid, random_below};

const PACKET_LIMIT: usize = 64;
const MEMORY_LIMIT: usize = 8 * 1024 * 1024;

type Packets = Vec<(Vec<u8>, Duration)>;

pub(super) struct Script {
    lua: Lua,
    deadline: Arc<Mutex<Instant>>,
}

impl Script {
    pub(super) fn load(name: &str) -> io::Result<Self> {
        let path = resolve(name)?;
        let source = std::fs::read(&path)?;
        Self::new(&source, &path.display().to_string()).map_err(invalid)
    }

    fn new(source: &[u8], name: &str) -> mlua::Result<Self> {
        let lua = Lua::new_with(StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::OS, LuaOptions::default())?;
        lua.set_memory_limit(MEMORY_LIMIT)?;
        let deadline = Arc::new(Mutex::new(Instant::now() + Duration::from_secs(120)));
        configure(&lua, &deadline)?;
        let hook = deadline.clone();
        lua.set_hook(HookTriggers::new().every_nth_instruction(4096), move |_, _| {
            check_deadline(&hook)?;
            Ok(VmState::Continue)
        })?;
        lua.load(source).set_name(name).set_mode(ChunkMode::Text).exec()?;
        lua.globals().get::<Function>("HandleNoise")?;
        Ok(Self { lua, deadline })
    }

    pub(super) fn packets(&mut self, peer: SocketAddr) -> mlua::Result<Packets> {
        *self.deadline.lock().expect("noise Lua deadline") = Instant::now() + Duration::from_secs(1);
        let plan = Plan(Arc::new(Mutex::new(Some(Emission::default()))));
        let hook = self.lua.globals().get::<Function>("HandleNoise")?;
        let result: mlua::Result<Value> = hook.call((plan.clone(), peer.to_string()));
        let emission = plan.0.lock().expect("noise Lua plan").take().expect("active noise Lua plan");
        match result? {
            Value::Nil => Ok(emission.packets),
            Value::String(error) => Err(mlua::Error::runtime(error.to_string_lossy())),
            _ => Err(mlua::Error::runtime("HandleNoise must return nil or an error string")),
        }
    }
}

fn resolve(name: &str) -> io::Result<PathBuf> {
    let path = Path::new(name);
    if !path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("lua")) {
        return Err(invalid("noise script file extension must be .lua"));
    }
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let locations = [
        std::env::var_os("XRAY_LOCATION_CONFDIR").map(PathBuf::from),
        std::env::var_os("XRAY_LOCATION_CONFIG").map(PathBuf::from),
        Some(PathBuf::from(".")),
        std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_path_buf)),
    ];
    for directory in locations.into_iter().flatten().filter(|path| !path.as_os_str().is_empty()) {
        let found = directory.join(path);
        match found.metadata() {
            Ok(_) => return Ok(found),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, format!("noise script {name:?}")))
}

fn configure(lua: &Lua, deadline: &Arc<Mutex<Instant>>) -> mlua::Result<()> {
    let globals = lua.globals();
    for name in [
        "collectgarbage", "coroutine", "dofile", "getfenv", "getmetatable", "load", "loadfile",
        "loadstring", "module", "newproxy", "package", "print", "rawget", "rawset", "setfenv",
        "setmetatable",
    ] {
        globals.set(name, Value::Nil)?;
    }
    globals.set("tostring", lua.create_function(|_, value: Value| Ok(log_value(value)))?)?;
    let string: Table = globals.get("string")?;
    string.set("dump", Value::Nil)?;
    let math: Table = globals.get("math")?;
    math.set("randomseed", Value::Nil)?;
    let os: Table = globals.get("os")?;
    let names = os.clone().pairs::<String, Value>().map(|pair| pair.map(|(name, _)| name)).collect::<mlua::Result<Vec<_>>>()?;
    for name in names {
        if !matches!(name.as_str(), "clock" | "date" | "difftime" | "time") {
            os.set(name, Value::Nil)?;
        }
    }
    for name in ["pcall", "xpcall"] {
        let call: Function = globals.get(name)?;
        let deadline = deadline.clone();
        globals.set(name, lua.create_function(move |_, args: MultiValue| {
            let result = call.call::<MultiValue>(args);
            // Propagate the deadline through protected calls in the script.
            check_deadline(&deadline)?;
            result
        })?)?;
    }

    let noise = lua.create_table()?;
    noise.set("Random", lua.create_function(|lua, len: f64| {
        let mut out = Vec::new();
        random_bytes(&mut out, bounded(len)?).map_err(mlua::Error::external)?;
        lua.create_string(out)
    })?)?;
    noise.set("RandomBetween", lua.create_function(|_, (min, max): (f64, f64)| {
        if min > max {
            return Err(mlua::Error::runtime("noise RandomBetween has a reversed range"));
        }
        let min = bounded(min)? as u32;
        let max = bounded(max)? as u32;
        Ok(min + random_below(max - min + 1))
    })?)?;
    let log = lua.create_table()?;
    for name in ["Debug", "Info", "Warning", "Error"] {
        log.set(name, lua.create_function(move |_, args: MultiValue| {
            if matches!(name, "Warning" | "Error") {
                let message: String = args.into_iter().map(log_value).collect();
                eprintln!("finalmask noise Lua {name}: {message}");
            }
            Ok(())
        })?)?;
    }
    lua.set_named_registry_value("xray.finalmask.noise", noise)?;
    lua.set_named_registry_value("xray.log", log)?;
    globals.set("require", lua.create_function(|lua, name: String| {
        match name.as_str() {
            "xray.finalmask.noise" | "xray.log" => lua.named_registry_value::<Table>(&name),
            "os" | "string" | "table" | "math" => lua.globals().get::<Table>(name),
            _ => Err(mlua::Error::runtime(format!("unknown noise Lua module {name:?}"))),
        }
    })?)?;
    Ok(())
}

fn check_deadline(deadline: &Mutex<Instant>) -> mlua::Result<()> {
    if Instant::now() >= *deadline.lock().expect("noise Lua deadline") {
        return Err(mlua::Error::runtime("noise Lua time limit"));
    }
    Ok(())
}

fn log_value(value: Value) -> String {
    match value {
        Value::Nil => "nil".to_owned(),
        Value::String(text) => text.to_string_lossy(),
        Value::Boolean(value) => value.to_string(),
        Value::Integer(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        _ => "<opaque>".to_owned(),
    }
}

#[derive(Default)]
struct Emission {
    packets: Packets,
    bytes: usize,
}

#[derive(Clone)]
struct Plan(Arc<Mutex<Option<Emission>>>);

impl Plan {
    fn append(&self, packet: Vec<u8>, delay: Option<f64>) -> mlua::Result<()> {
        let delay = Duration::from_millis(bounded(delay.unwrap_or_default())? as u64);
        let mut state = self.0.lock().expect("noise Lua plan");
        let plan = state.as_mut().ok_or_else(|| mlua::Error::runtime("noise plan only accepts packets during HandleNoise"))?;
        if plan.packets.len() == PACKET_LIMIT || plan.bytes + packet.len() > VALUE_LIMIT {
            return Err(mlua::Error::runtime("noise plan packet or byte limit exceeded"));
        }
        plan.bytes += packet.len();
        plan.packets.push((packet, delay));
        Ok(())
    }
}

impl UserData for Plan {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("Add", |_, plan, (packet, delay): (LuaString, Option<f64>)| {
            plan.append(packet.as_bytes().to_vec(), delay)
        });
        methods.add_method("AddRandom", |_, plan, (size, delay): (f64, Option<f64>)| {
            let mut bytes = Vec::new();
            random_bytes(&mut bytes, bounded(size)?).map_err(mlua::Error::external)?;
            plan.append(bytes, delay)
        });
    }
}

fn bounded(value: f64) -> mlua::Result<usize> {
    if !(0.0..=VALUE_LIMIT as f64).contains(&value) {
        return Err(mlua::Error::runtime("noise Lua numeric value exceeds 0..65535"));
    }
    Ok(value as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_lua_api_builds_a_packet_plan() {
        let source = br#"
            local noise = require("xray.finalmask.noise")
            function HandleNoise(plan, addr)
                assert(addr == "127.0.0.1:1")
                plan:Add("\22\3\1")
                plan:Add(noise.Random(noise.RandomBetween(16, 16)), 1)
                plan:AddRandom(5)
            end
        "#;
        let mut script = Script::new(source, "fixture.lua").unwrap();
        let plan = script.packets("127.0.0.1:1".parse().unwrap()).unwrap();
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0], (vec![22, 3, 1], Duration::ZERO));
        assert_eq!(plan[1].0.len(), 16);
        assert_eq!(plan[1].1, Duration::from_millis(1));
        assert_eq!(plan[2].0.len(), 5);
    }
}
