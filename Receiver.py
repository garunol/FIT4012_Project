import json
import base64
import hashlib
import os
from crypto_utils import *
from datetime import datetime

print("\U0001f513 [Receiver] Ready!")

# Load khóa
receiver_priv = open("receiver_private.pem", "rb").read()
sender_pub = open("sender_public.pem", "rb").read()

# Đọc packet và secure_packet
with open("packet.json", "r") as f:
    packet = json.load(f)
with open("secure_packet.json", "r") as f:
    secure_packet = json.load(f)

# ======== BƯỚC 1: Giải mã DES key ========
encrypted_des_key = base64.b64decode(packet["encrypted_des_key"])
des_key = rsa_decrypt(encrypted_des_key, receiver_priv)

# ======== BƯỚC 2: Xác thực metadata ========
metadata = base64.b64decode(packet["metadata"])
signature = base64.b64decode(packet["metadata_sig"])
if not rsa_verify(metadata, signature, sender_pub):
    raise Exception("❌ Xác thực metadata thất bại!")

file_name, timestamp = metadata.decode().split("|")
print(f"📎 Metadata: file = {file_name}, timestamp = {timestamp}")

# ======== BƯỚC 3: Giải mã nội dung ========
cipher_data = base64.b64decode(secure_packet["cipher"])
iv, cipher_text = cipher_data[:8], cipher_data[8:]

hash_input = cipher_text
if "expiration" in secure_packet:
    expiration = secure_packet["expiration"]
    hash_input += str(expiration).encode()
    expire_dt = datetime.fromtimestamp(int(expiration))
    if datetime.now() > expire_dt:
        raise Exception("❌ Gói tin đã hết hạn!")

# Kiểm tra tính toàn vẹn
calculated_hash = hashlib.sha256(hash_input).hexdigest()
if calculated_hash != secure_packet["hash"]:
    raise Exception("❌ Hash không khớp!")

# Xác thực chữ ký bản mã
cipher_sig = base64.b64decode(secure_packet["sig"])
if not rsa_verify(cipher_text, cipher_sig, sender_pub):
    raise Exception("❌ Chữ ký bản mã không hợp lệ!")

# Giải mã bản mã
plaintext = des_decrypt_cfb(cipher_text, des_key, iv)

# Nếu là văn bản, hiển thị
if file_name.endswith(".txt") or file_name.endswith(".md"):
    try:
        print("📩 Nội dung tin nhắn:", plaintext.decode())
    except:
        print("📩 Nội dung không thể hiển thị được (bị lỗi mã hóa)")
else:
    # Nếu là file nhị phân, lưu lại
    out_path = f"decrypted_{file_name}"
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"📁 File đã được giải mã và lưu tại: {out_path}")
