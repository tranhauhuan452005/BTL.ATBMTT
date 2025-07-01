# FileName: MultipleFiles/cipher_utils.py
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import base64
import os

# --- Khởi tạo và quản lý khóa ---
# Để đảm bảo khóa không thay đổi mỗi lần khởi động, chúng ta sẽ lưu chúng vào file
# Trong môi trường sản phẩm, bạn nên sử dụng một hệ thống quản lý khóa an toàn hơn (ví dụ: HashiCorp Vault)

RSA_PRIVATE_KEY_PATH = 'rsa_private_key.pem'
RSA_PUBLIC_KEY_PATH = 'rsa_public_key.pem'
AES_KEY_PATH = 'aes_key.bin'

def generate_and_save_keys():
    """Tạo và lưu trữ các khóa RSA và AES nếu chúng chưa tồn tại."""
    global rsa_private_key, rsa_public_key, aes_key

    # RSA Keys
    if not os.path.exists(RSA_PRIVATE_KEY_PATH) or not os.path.exists(RSA_PUBLIC_KEY_PATH):
        rsa_key = RSA.generate(2048)
        rsa_private_key = rsa_key.export_key()
        rsa_public_key = rsa_key.publickey().export_key()

        with open(RSA_PRIVATE_KEY_PATH, 'wb') as f:
            f.write(rsa_private_key)
        with open(RSA_PUBLIC_KEY_PATH, 'wb') as f:
            f.write(rsa_public_key)
        print("Generated and saved new RSA keys.")
    else:
        with open(RSA_PRIVATE_KEY_PATH, 'rb') as f:
            rsa_private_key = f.read()
        with open(RSA_PUBLIC_KEY_PATH, 'rb') as f:
            rsa_public_key = f.read()
        print("Loaded existing RSA keys.")

    # AES Key
    if not os.path.exists(AES_KEY_PATH):
        aes_key = get_random_bytes(16) # AES-128
        with open(AES_KEY_PATH, 'wb') as f:
            f.write(aes_key)
        print("Generated and saved new AES key.")
    else:
        with open(AES_KEY_PATH, 'rb') as f:
            aes_key = f.read()
        print("Loaded existing AES key.")

# Gọi hàm này khi module được import để đảm bảo khóa luôn sẵn sàng
generate_and_save_keys()

# --- Hàm mã hóa/giải mã Caesar Cipher ---
def caesar_cipher_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                result += chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
        else:
            result += char
    return result

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

# --- Hàm mã hóa/giải mã Vigenère Cipher ---
def vigenere_cipher_encrypt(text, key):
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char.lower()) - ord('a')
            if char.islower():
                result += chr((ord(char) - ord('a') + key_shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + key_shift) % 26 + ord('A'))
            key_index += 1
        else:
            result += char
    return result

def vigenere_cipher_decrypt(text, key):
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char.lower()) - ord('a')
            if char.islower():
                result += chr((ord(char) - ord('a') - key_shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') - key_shift) % 26 + ord('A'))
            key_index += 1
        else:
            result += char
    return result

# --- Hàm mã hóa/giải mã RSA ---
def rsa_encrypt(public_key_bytes, message):
    public_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def rsa_decrypt(private_key_bytes, encrypted_message):
    private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# --- Hàm mã hóa/giải mã AES ---
def aes_encrypt(key_bytes, message):
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def aes_decrypt(key_bytes, iv_and_ciphertext):
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode()

