# 本地Arti补丁

基线为`arti-client 0.47.0`发布包。压缩包、Git提交和官方许可来源见[SOURCE.json](SOURCE.json)。保留发布包的源码、manifest、原始作者和说明，另从同一固定官方Git提交补入完整`LICENSE-MIT`与`LICENSE-APACHE`。本地修改不会将第三方代码改授为项目GPL许可。

运行补丁修改`src/builder.rs`与`src/client.rs`。本仓库另省略两个Cargo manifest中的个人联系条目，保留项目作者、原版权和完整许可证；完整发布包及摘要仍见SOURCE.json。这是发布元数据调整，不改变运行接口。

`TorClientBuilder::protocol_shutdown_handler`保存可选的可信嵌入回调。回调经`create_impl`和`NotConstructedInner`传入原有协议状态监测任务。`dispatch_embedded_protocol_failure`在存在回调时同步调用并返回；未提供回调时把原始错误交回既有打印、等待和`process::exit(1)`分支。

原有`protostatus::enforce_protocol_recommendations`不变。启动时，新的缓存协议要求缺少必需项会直接返回错误。运行时，监测任务只处理新的协议建议，忽略早于软件发布时间的数据；缺少必需协议时调用fatal处置然后返回。没有移除签名共识验证、必需协议要求或上游推荐项提示。

回调是可信宿主契约，返回前必须同步发布不可恢复失败并请求取消所属client。失败发布后开始准入的操作必须拒绝。已准入且与发布重叠的poll或内核I/O不能瞬时撤回，在下一取消观察点停止，资源另行等待真实join。回调返回不保证已有操作静默或资源排空。kerlico先保存命名ServiceContext的typed首因，再取消该服务，其他命名服务不受此回调控制。

原两个局部回归验证必需协议判定及缺省fatal分支输入。kerlico新增受控`DirProvider`回归，通过生产builder、`RunningInner`及实际协议事件watcher触发注册的handler，分别覆盖初始缓存拒绝和运行fatal。测试用`experimental-api`与`error_detail`只在kerlico开发依赖中启用。当前修订尚未执行这些测试，不能登记补丁已验收。
