import base64
import hashlib
import time
import json
from crypto_utils import *
from IPython.display import display, clear_output, JSON, HTML
import ipywidgets as widgets

print("\U0001f512 [Sender] Hello Mr.B, I'm A!")
print("\U0001f513 [Receiver] Hi A, I'm Ready!")

# Load khóa
sender_priv = open("sender_private.pem", "rb").read()
receiver_pub = open("receiver_public.pem", "rb").read()

# === Chọn chế độ: nhập tay hoặc file ===
mode = input("🔘 Chọn chế độ (1: Nhập tay, 2: Mã hóa file): ")

if mode == "1":
    message = input("📝 Nhập nội dung tin nhắn: ").encode()
    file_name = "message_input.txt"
    with open(file_name, "wb") as f:
        f.write(message)
elif mode == "2":
    file_name = input("📁 Nhập tên file cần mã hóa (vd: song.mp3, note.txt): ")
    try:
        with open(file_name, "rb") as f:
            message = f.read()
        print(f"✅ Đã đọc file: {file_name}, kích thước: {len(message)} byte")
    except FileNotFoundError:
        print("❌ Không tìm thấy file!")
        message = None
else:
    print("❌ Chế độ không hợp lệ!")
    message = None

# Nếu có dữ liệu thì tiếp tục mã hóa
if message:
    # === Bước 1: Sinh Session Key (DES)
    des_key = generate_des_key()

    # === Bước 2: Ký metadata (file name + timestamp)
    timestamp = int(time.time())
    metadata = f"{file_name}|{timestamp}".encode()
    metadata_signature = rsa_sign(metadata, sender_priv)

    # === Bước 3: Mã hóa SessionKey bằng RSA
    encrypted_des_key = rsa_encrypt(des_key, receiver_pub)

    # === Gói trao khóa ===
    packet = {
        "metadata": base64.b64encode(metadata).decode(),
        "metadata_sig": base64.b64encode(metadata_signature).decode(),
        "encrypted_des_key": base64.b64encode(encrypted_des_key).decode()
    }

    # === Bước 4: Mã hóa dữ liệu & Kiểm tra toàn vẹn ===
    iv, cipher_text = des_encrypt_cfb(message, des_key)
    expiration = timestamp + 5000  # hạn 1 phút
    combined = cipher_text + str(expiration).encode()
    hash_digest = hashlib.sha256(combined).hexdigest()
    cipher_signature = rsa_sign(cipher_text, sender_priv)

    secure_packet = {
        "cipher": base64.b64encode(iv + cipher_text).decode(),
        "hash": hash_digest,
        "expiration": str(expiration),
        "sig": base64.b64encode(cipher_signature).decode()
    }

    # === Giao diện hiển thị Colab ===
    output_area = widgets.Output()
    buttons_area = widgets.Output()
    current_display = {"type": None}
    toggle_state = {'shown': False}

    btn_send_fake = widgets.Button(description="📦 Gửi gói xong.", layout=widgets.Layout(border='none', padding='0px', margin='0px'))
    btn_send_fake.style.button_color = 'transparent'
    btn_send_fake.add_class("fake-text-button")

    display(HTML("""
    <style>
        .fake-text-button button {
            background: none !important;
            border: none !important;
            padding: 0px !important;
            margin: 0px !important;
            font-weight: normal !important;
            color: inherit !important;
            cursor: pointer;
        }
    </style>
    """))

    btn_packet = widgets.Button(description="📂 Xem gói Packet")
    btn_secure = widgets.Button(description="🔐 Xem gói Secure Packet")
    btn_packet.layout.display = "none"
    btn_secure.layout.display = "none"

    def on_send_click(b):
        toggle_state['shown'] = not toggle_state['shown']
        display_mode = "inline-block" if toggle_state['shown'] else "none"
        btn_packet.layout.display = display_mode
        btn_secure.layout.display = display_mode
    btn_send_fake.on_click(on_send_click)

    def toggle_packet(b):
        with output_area:
            clear_output()
            if current_display["type"] == "packet":
                current_display["type"] = None
            else:
                current_display["type"] = "packet"
                print("📦 Nội dung gói Packet:")
                display(JSON(packet))
    btn_packet.on_click(toggle_packet)

    def toggle_secure(b):
        with output_area:
            clear_output()
            if current_display["type"] == "secure_packet":
                current_display["type"] = None
            else:
                current_display["type"] = "secure_packet"
                print("🔐 Nội dung gói Secure Packet:")
                display(JSON(secure_packet))
    btn_secure.on_click(toggle_secure)

    display(btn_send_fake)
    display(widgets.HBox([btn_packet, btn_secure]))
    display(output_area)

    with open("packet.json", "w") as f:
        json.dump(packet, f)
    with open("secure_packet.json", "w") as f:
        json.dump(secure_packet, f)
    print("✅ Gói tin đã được mã hóa và lưu lại.")
