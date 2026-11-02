"""只供互通工具建立合成的 v2 账户和节点成员。"""

import copy
import uuid


_TEST_PASSWORD_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$"
    "dGVzdC1zYWx0LTEyMzQ1Ng$"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


def bind_members(config, node, credentials):
    """将明确拆出的原生凭据绑定到独立测试账户，不解释协议线格式。"""
    config["version"] = 2
    accounts = config.setdefault("accounts", [])
    members = []
    existing = {account["user_id"] for account in accounts}
    for index, native in enumerate(credentials):
        identity = str(uuid.uuid5(uuid.NAMESPACE_URL, f"kerlico-test/{node['tag']}/{index}"))
        if identity in existing:
            raise ValueError("同一测试节点的成员不能重复装配")
        existing.add(identity)
        accounts.append({
            "user_id": identity,
            "username": "test_" + identity,
            "password_hash": _TEST_PASSWORD_HASH,
        })
        members.append({
            "user_id": identity,
            "credential_epoch": 1,
            "native_credential": copy.deepcopy(native),
        })
    node["members"] = members
