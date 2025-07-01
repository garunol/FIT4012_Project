from Crypto.PublicKey import RSA

# Sinh và lưu khóa
def generate_keys():
    sender_key = RSA.generate(2048)
    receiver_key = RSA.generate(2048)

    with open("sender_private.pem", "wb") as f:
        f.write(sender_key.export_key())
    with open("sender_public.pem", "wb") as f:
        f.write(sender_key.publickey().export_key())

    with open("receiver_private.pem", "wb") as f:
        f.write(receiver_key.export_key())
    with open("receiver_public.pem", "wb") as f:
        f.write(receiver_key.publickey().export_key())

generate_keys()
print("✅ Đã tạo và lưu cặp khóa RSA cho Người Gửi và Người Nhận.")
