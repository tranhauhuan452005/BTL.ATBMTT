from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)
# Hàm mã hóa và giải mã Caesar Cipher
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

# Ví dụ sử dụng
text = "Hello, World!"
shift = 3
encrypted = caesar_cipher_encrypt(text, shift)
decrypted = caesar_cipher_decrypt(encrypted, shift)
print(f"Original: {text}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")

# Hàm mã hóa và giải mã Vigenère Cipher
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

# Ví dụ sử dụng
text = "Hello, World!"
key = "KEY"
encrypted = vigenere_cipher_encrypt(text, key)
decrypted = vigenere_cipher_decrypt(encrypted, key)
print(f"Original: {text}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")

# Mã hóa và giải mã RSA

# Tạo khóa RSA
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Mã hóa
def rsa_encrypt(public_key_str, message):
    public_key = RSA.import_key(public_key_str)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# Giải mã
def rsa_decrypt(private_key_str, encrypted_message):
    private_key = RSA.import_key(private_key_str)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# Ví dụ sử dụng
text = "Hello, World!"
encrypted = rsa_encrypt(public_key, text)
decrypted = rsa_decrypt(private_key, encrypted)
print(f"Original: {text}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")

# AES 
# Tạo khóa AES
key = get_random_bytes(16)

# Mã hóa
def aes_encrypt(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

# Giải mã
def aes_decrypt(key, iv_and_ciphertext):
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode()

# Ví dụ sử dụng
text = "Hello, World!"
encrypted = aes_encrypt(key, text)
decrypted = aes_decrypt(key, encrypted)
print(f"Original: {text}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")

if __name__ == '__main__':
    app.run(debug=True)