from flask import Flask, render_template, request, jsonify
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)

# ---------------------------
# Reversible Techniques
# ---------------------------

def base64_encode(text):
    return base64.urlsafe_b64encode(text.encode()).decode()

def base64_decode(text):
    return base64.urlsafe_b64decode(text.encode()).decode()

def caesar_encrypt(text, shift=3):
    result = ''
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

def aes_encrypt(text, key_str):
    key = base64.urlsafe_b64encode(hashlib.sha256(key_str.encode()).digest())
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def aes_decrypt(token, key_str):
    key = base64.urlsafe_b64encode(hashlib.sha256(key_str.encode()).digest())
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()

def rot13(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    ))

def xor_encrypt(text, key):
    key_bytes = key.encode()
    return base64.urlsafe_b64encode(bytes([c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(text.encode())])).decode()

def xor_decrypt(ciphertext, key):
    key_bytes = key.encode()
    decoded = base64.urlsafe_b64decode(ciphertext.encode())
    return ''.join([chr(b ^ key_bytes[i % len(key_bytes)]) for i, b in enumerate(decoded)])

def reverse_string(text):
    return text[::-1]

# ---------------------------
# Web Functions
# ---------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    text = request.form.get('text')
    key = request.form.get('key') if request.form.get('key') else "defaultMasterKey123!"  # Default key if none provided

    if not text:
        return jsonify({"error": "Input text cannot be empty."}), 400

    techniques = request.form.getlist('techniques')
    try:
        for tech in techniques:
            if tech == "Base64":
                text = base64_encode(text)
            elif tech == "Caesar":
                text = caesar_encrypt(text)
            elif tech == "AES":
                text = aes_encrypt(text, key)
            elif tech == "ROT13":
                text = rot13(text)
            elif tech == "XOR":
                text = xor_encrypt(text, key)
            elif tech == "Reverse":
                text = reverse_string(text)

        return jsonify({"encrypted_text": text})

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    text = request.form.get('text')
    key = request.form.get('key') if request.form.get('key') else "defaultMasterKey123!"  # Default key if none provided

    if not text:
        return jsonify({"error": "Encrypted text cannot be empty."}), 400

    techniques = request.form.getlist('techniques')[::-1]  # reverse order
    try:
        for tech in techniques:
            if tech == "Base64":
                text = base64_decode(text)
            elif tech == "Caesar":
                text = caesar_decrypt(text)
            elif tech == "AES":
                text = aes_decrypt(text, key)
            elif tech == "ROT13":
                text = rot13(text)
            elif tech == "XOR":
                text = xor_decrypt(text, key)
            elif tech == "Reverse":
                text = reverse_string(text)

        return jsonify({"decrypted_text": text})

    except InvalidToken:
        return jsonify({"error": "Invalid token or wrong key."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
