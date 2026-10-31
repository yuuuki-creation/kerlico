# HTTP 代理验证记录

日期：2026-10-31。基于 `6cbb3f9` 的开发工作树，全部构建与测试在 perf-01，Rust 1.99.1、Linux x86_64；没有本地构建测试。

首轮 4 项集成中 3 项通过，无认证入口按服务端节点配置被独立认证校验拒绝。增加单独的回环 `local_inbounds` 后，第三快照 4 项 HTTP 集成、6 项 SOCKS 集成与 7 项引擎回归、格式、严格 Clippy 和双协议 CLI 构建通过。TLS、半关闭、普通 POST/分块响应、逐跳及认证字段剥离、错误配置的限定用例已实跑。

固定 sing-box 双向互通首轮明文 HTTP 和 TLS 服务端方向通过，TLS 客户端方向失败。将测试证书的 BasicConstraints 改为 CA:FALSE 后，两方向、明文/TLS、两类节点与两类目标的 HTTP **16/16 项 TCP 检查通过**；没有修改生产 TLS 验证或增加跳过证书开关。原失败保留在私有快照记录中。

正式工具为 `tools/interop_local_proxies.py`，与 SOCKS 合并矩阵第三轮 52 项通过、0 项协议失败、4 项参考入口零包限制（属于 SOCKS，不是 HTTP UDP 能力）。HTTP 不声明 UDP。最终整树与快照摘要仍待补充，新增业务 peer 元数据已通过相关包级回归。

随后增加活动 CONNECT 连接在引擎排空期间继续收发、EOF 后结束及同端口重绑，以及慢请求头和携带请求体 CONNECT 的拒绝回归；HTTP 合计 6 项集成测试通过。与公共层及 SOCKS 合计 28 项包级测试和严格 Clippy 通过，最终冻结整树复验另行记录。参考对端与互通 CLI 的确切版本、摘要见[SOCKS 同批快照](socks.md)。

待统一执行：包级测试、格式与 Clippy、正式 CLI、固定 Xray/sing-box 双向互通及工作区回归。已编写用例覆盖明文/TLS CONNECT、认证、半关闭、2xx 首包、失败回复、普通 POST/分块响应、逐跳与凭据剥离、错误 Host/URI；其他矩阵按研究记录继续补足。
