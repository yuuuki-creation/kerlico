use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;
use serde_json::Value;

use super::{decode_bytes, invalid, malformed, validate_name, MAX_HEADER};

pub(super) type Vars = HashMap<String, Vec<u8>>;
pub(super) type Sizes = HashMap<String, usize>;

#[derive(Default)]
pub(super) struct Context {
    pub(super) vars: Vars,
    pub(super) addrs: Option<(SocketAddr, SocketAddr)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawExpr {
    op: String,
    args: Vec<RawArg>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawArg {
    #[serde(rename = "type")]
    kind: String,
    bytes: Option<Value>,
    u64: Option<u64>,
    reuse: String,
    metadata: String,
    transform: Option<RawExpr>,
}

#[derive(Clone)]
pub(super) struct Expr {
    op: Op,
    args: Vec<Arg>,
}

#[derive(Clone)]
enum Arg {
    Bytes(Vec<u8>),
    Number(u64),
    Var(String),
    Metadata(String),
    Expr(Expr),
}

#[derive(Clone, Copy)]
enum Op {
    Concat,
    Slice,
    Pack { len: usize, big_endian: bool },
    Pad,
    Truncate,
    Xor(u64),
    Add,
    Sub,
    And,
    Or,
    Shl,
    Shr,
}

impl RawExpr {
    pub(super) fn build(self) -> io::Result<Expr> {
        let (op, count) = match self.op.as_str() {
            "concat" => (Op::Concat, self.args.len().max(1)),
            "slice" => (Op::Slice, 3),
            "be16" => (Op::Pack { len: 2, big_endian: true }, 1),
            "be32" => (Op::Pack { len: 4, big_endian: true }, 1),
            "le16" => (Op::Pack { len: 2, big_endian: false }, 1),
            "le32" => (Op::Pack { len: 4, big_endian: false }, 1),
            "le64" => (Op::Pack { len: 8, big_endian: false }, 1),
            "pad" => (Op::Pad, 3),
            "truncate" => (Op::Truncate, 2),
            "xor16" => (Op::Xor(u16::MAX.into()), 2),
            "xor32" => (Op::Xor(u32::MAX.into()), 2),
            "add" => (Op::Add, 2),
            "sub" => (Op::Sub, 2),
            "and" => (Op::And, 2),
            "or" => (Op::Or, 2),
            "shl" => (Op::Shl, 2),
            "shr" => (Op::Shr, 2),
            _ => return Err(invalid(format!("unsupported header-custom transform {:?}", self.op))),
        };
        if self.args.len() != count {
            return Err(invalid(format!("header-custom transform {} expects {count} arguments", self.op)));
        }
        let args = self.args.into_iter().map(RawArg::build).collect::<io::Result<_>>()?;
        Ok(Expr { op, args })
    }
}

impl RawArg {
    fn build(self) -> io::Result<Arg> {
        let count = [self.bytes.is_some(), self.u64.is_some(), !self.reuse.is_empty(), !self.metadata.is_empty(), self.transform.is_some()]
            .into_iter().filter(|value| *value).count();
        if count != 1 {
            return Err(invalid("header-custom transform argument expects one value"));
        }
        if let Some(bytes) = self.bytes {
            return decode_bytes(bytes, &self.kind).map(Arg::Bytes);
        }
        if let Some(number) = self.u64 {
            return Ok(Arg::Number(number));
        }
        if !self.reuse.is_empty() {
            validate_name(&self.reuse)?;
            return Ok(Arg::Var(self.reuse));
        }
        if !self.metadata.is_empty() {
            return Ok(Arg::Metadata(self.metadata));
        }
        Ok(Arg::Expr(self.transform.expect("one transform argument").build()?))
    }
}

enum Evaluated {
    Bytes(Vec<u8>),
    Number(u64),
}

impl Evaluated {
    fn number(self) -> io::Result<u64> {
        match self {
            Self::Number(number) => Ok(number),
            Self::Bytes(_) => Err(malformed("header-custom transform expects a u64")),
        }
    }

    fn bytes(self) -> io::Result<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Number(_) => Err(malformed("header-custom transform expects bytes")),
        }
    }
}

impl Arg {
    fn measure(&self, sizes: &Sizes) -> io::Result<usize> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.len()),
            Self::Var(name) => sizes.get(name).copied().ok_or_else(|| malformed("unknown header-custom variable")),
            Self::Expr(expr) => expr.measure(sizes),
            _ => Err(malformed("header-custom argument has no byte width")),
        }
    }

    fn eval(&self, context: &Context) -> io::Result<Evaluated> {
        Ok(match self {
            Self::Bytes(bytes) => Evaluated::Bytes(bytes.clone()),
            Self::Number(value) => Evaluated::Number(*value),
            Self::Var(name) => Evaluated::Bytes(context.vars.get(name).ok_or_else(|| malformed("unknown header-custom variable"))?.clone()),
            Self::Metadata(name) => Evaluated::Number(metadata(name, context.addrs).ok_or_else(|| malformed("unknown header-custom metadata"))?),
            Self::Expr(expr) => expr.eval(context)?,
        })
    }
}

impl Expr {
    pub(super) fn measure(&self, sizes: &Sizes) -> io::Result<usize> {
        match self.op {
            Op::Concat => self.args.iter().try_fold(0, |len, arg| {
                bounded(len + arg.measure(sizes)?)
            }),
            Op::Pack { len, .. } => Ok(len),
            Op::Slice | Op::Pad | Op::Truncate => {
                let index = if matches!(self.op, Op::Slice) { 2 } else { 1 };
                let Arg::Number(value) = self.args[index] else {
                    return Err(malformed("header-custom transform length must be a constant u64"));
                };
                bounded_number(value)
            }
            _ => Err(malformed("header-custom transform has no byte width")),
        }
    }

    pub(super) fn bytes(&self, context: &Context) -> io::Result<Vec<u8>> {
        self.eval(context)?.bytes()
    }

    fn eval(&self, context: &Context) -> io::Result<Evaluated> {
        let bytes = |index: usize| self.args[index].eval(context)?.bytes();
        let number = |index: usize| self.args[index].eval(context)?.number();
        let result = match self.op {
            Op::Concat => {
                let mut out = Vec::new();
                for arg in &self.args {
                    let part = arg.eval(context)?.bytes()?;
                    bounded(out.len() + part.len())?;
                    out.extend(part);
                }
                out
            }
            Op::Pack { len, big_endian } => {
                let value = number(0)?;
                if len < 8 && value >= (1 << (len * 8)) {
                    return Err(malformed("header-custom integer exceeds pack width"));
                }
                if big_endian {
                    value.to_be_bytes()[8-len..].to_vec()
                } else {
                    value.to_le_bytes()[..len].to_vec()
                }
            }
            Op::Slice | Op::Truncate => {
                let source = bytes(0)?;
                let (start, len) = if matches!(self.op, Op::Slice) {
                    (bounded_number(number(1)?)?, bounded_number(number(2)?)?)
                } else {
                    (0, bounded_number(number(1)?)?)
                };
                source.get(start..start + len).ok_or_else(|| malformed("header-custom slice out of bounds"))?.to_vec()
            }
            Op::Pad => {
                let mut source = bytes(0)?;
                let len = bounded_number(number(1)?)?;
                let fill = bytes(2)?;
                if len < source.len() || fill.is_empty() {
                    return Err(malformed("invalid header-custom padding"));
                }
                source.extend(fill.into_iter().cycle().take(len - source.len()));
                source
            }
            op => {
                let left = number(0)?;
                let right = number(1)?;
                let result = match op {
                    Op::Xor(mask) if left <= mask && right <= mask => Some(left ^ right),
                    Op::Add => left.checked_add(right),
                    Op::Sub => left.checked_sub(right),
                    Op::And => Some(left & right),
                    Op::Or => Some(left | right),
                    Op::Shl if right < 64 && left <= u64::MAX >> right => Some(left << right),
                    Op::Shr if right < 64 => Some(left >> right),
                    _ => None,
                };
                return result.map(Evaluated::Number).ok_or_else(|| malformed("header-custom arithmetic out of range"));
            }
        };
        Ok(Evaluated::Bytes(result))
    }
}

fn bounded_number(value: u64) -> io::Result<usize> {
    bounded(usize::try_from(value).map_err(invalid)?)
}

fn bounded(len: usize) -> io::Result<usize> {
    if len > MAX_HEADER {
        return Err(invalid("header-custom byte count exceeds one MiB"));
    }
    Ok(len)
}

fn metadata(name: &str, addrs: Option<(SocketAddr, SocketAddr)>) -> Option<u64> {
    let (local, remote) = addrs?;
    let (addr, port) = match name {
        "local_port" | "dst_port_u16" => (local, true),
        "remote_port" | "src_port_u16" => (remote, true),
        "local_ip4_u32" | "dst_ip4_u32" => (local, false),
        "remote_ip4_u32" | "src_ip4_u32" => (remote, false),
        _ => return None,
    };
    if port {
        return Some(addr.port().into());
    }
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => Some(u32::from(ip).into()),
        IpAddr::V6(_) => None,
    }
}
