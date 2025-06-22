from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# 🔐 Encrypt message using AES
def encrypt_message(message, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    return encrypted

# 🔓 Decrypt AES message
def decrypt_message(encrypted, password):
    key = hashlib.sha256(password.encode()).digest()
    data = base64.b64decode(encrypted)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag).decode()
    return decrypted

# 🔁 Convert text to binary
def text_to_bin(text):
    return ''.join(format(ord(i), '08b') for i in text) + '1111111111111110'  # delimiter

# 🔁 Convert binary to text
def bin_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join([chr(int(b, 2)) for b in chars if b != '11111110'])

# 📥 Encode (hide) message in image
def encode(image_path, message, password, output_path):
    encrypted = encrypt_message(message, password)
    binary_msg = text_to_bin(encrypted)
    img = Image.open(image_path)
    pixels = list(img.getdata())

    new_pixels = []
    msg_index = 0
    for pixel in pixels:
        r, g, b = pixel
        if msg_index < len(binary_msg):
            r = (r & ~1) | int(binary_msg[msg_index])
            msg_index += 1
        if msg_index < len(binary_msg):
            g = (g & ~1) | int(binary_msg[msg_index])
            msg_index += 1
        if msg_index < len(binary_msg):
            b = (b & ~1) | int(binary_msg[msg_index])
            msg_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_path)
    print("✅ Message encrypted and hidden successfully in:", output_path)

# 📤 Decode (reveal) message from image
def decode(image_path, password):
    img = Image.open(image_path)
    binary_data = ""
    for pixel in list(img.getdata()):
        for color in pixel[:3]:
            binary_data += str(color & 1)
            if binary_data[-16:] == '1111111111111110':
                break
        if binary_data[-16:] == '1111111111111110':
            break

    binary_data = binary_data[:-16]  # Remove delimiter
    encrypted_text = bin_to_text(binary_data)
    try:
        decrypted = decrypt_message(encrypted_text, password)
        print("🔓 Hidden Message:\n", decrypted)
    except:
        print("❌ Decryption failed. Wrong password or corrupted data.")

# ------------------- TESTING AREA -------------------
if __name__ == "__main__":
    # Replace with your own values
    # Make sure test_image.png is present in same folder
    encode("test_image.jpg", "The launch code is 786shadow", "qurrathpass", "stego_final.png")
    decode("stego_final.png", "qurrathpass")
