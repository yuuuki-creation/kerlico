//! EasyTier 客户端出站：以 peer 身份加入虚拟网络，IP 包由共用用户态数据面处理。
mod client;
mod config;
#[cfg(test)]
mod tests;
pub use client::EasyTierFactory;

fn invalid() -> kerlico_core::Error {
    kerlico_core::Error::Config("EasyTier出站配置不合法".into())
}
