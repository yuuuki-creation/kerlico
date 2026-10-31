FROM debian:13-slim

# 仅为隔离的 SSH 对端测试提供合成账户，不修改 worker 用户或 SSH 服务。
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin proxy-test \
    && printf '%s\n' 'proxy-test:synthetic-ssh-fixture' | chpasswd \
    && mkdir -p /run/sshd

ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/keys/sshd_config"]
