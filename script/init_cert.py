import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def gen_rsa_pair():
    # 生成 2048 位 RSA 密钥
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    numbers = pub.public_numbers()
    # 提取 n 和 e 的 16 进制字符串
    n_hex = format(numbers.n, "x")
    e_hex = format(numbers.e, "x").zfill(6)  # 通常是 010001
    return priv, {"n": n_hex, "e": e_hex}


def create_certificate(entity_id, issuer, expire_date, priv_key, pub_data):
    # 1. 构造证书主体 (待签名部分)
    cert_body = {
        "id": entity_id,
        "issuer": issuer,
        "public_key": pub_data,
        "expire": expire_date,
    }
    # 2. 将主体转为稳定的字符串进行签名 (建议排序 key 以保证唯一性)
    data_to_sign = json.dumps(cert_body, sort_keys=True).encode()
    # 3. 计算签名 (使用私钥进行 RSA-PSS 或 PKCS1v15 签名)
    signature = priv_key.sign(
        data_to_sign,
        padding.PKCS1v15(),  # 简单直接，符合你 408 复习的经典 RSA 签名
        hashes.SHA256(),
    )
    # 4. 组装完整证书
    cert_body["sign"] = signature.hex()
    return cert_body


# --- 生成 Client 证书 --
client_priv, client_pub = gen_rsa_pair()
client_cert = create_certificate(
    "CLIENT_001", "MY_ROOT_CA", "2026-12-31", client_priv, client_pub
)
# --- 生成 V (堡垒机) 证书 --
v_priv, v_pub = gen_rsa_pair()
v_cert = create_certificate("SERVER_V_001", "MY_ROOT_CA", "2026-12-31", v_priv, v_pub)
# 保存结果
with open("cert_client.json", "w") as f:
    json.dump(client_cert, f, indent=2)
with open("cert_v.json", "w") as f:
    json.dump(v_cert, f, indent=2)
print("Certificates generated successfully.")