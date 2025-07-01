from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import base64
import os
import logging
import re
from datetime import datetime
from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import base64
import os
import logging
import re
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
# --- Khởi tạo và quản lý khóa ---
# Để đảm bảo khóa không thay đổi mỗi lần khởi động, chúng ta sẽ lưu chúng vào file
# Trong môi trường sản phẩm, bạn nên sử dụng một hệ thống quản lý khóa an toàn hơn (ví dụ: HashiCorp Vault)

RSA_PRIVATE_KEY_PATH = 'rsa_private_key.pem'
RSA_PUBLIC_KEY_PATH = 'rsa_public_key.pem'
AES_KEY_PATH = 'aes_key.bin'

# Khai báo các biến global cho RSA và AES keys
rsa_private_key = None
rsa_public_key = None
aes_key = None

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

# Gọi hàm này để đảm bảo khóa được tạo/tải khi ứng dụng khởi động
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
    # Chuẩn hóa key: chỉ lấy chữ cái và chuyển về chữ hoa để tính shift
    clean_key = "".join(filter(str.isalpha, key)).upper()
    
    if not clean_key:
        return text

    for char in text:
        if char.isalpha():
            key_char = clean_key[key_index % len(clean_key)]
            key_shift = ord(key_char) - ord('A')
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
    # Chuẩn hóa key: chỉ lấy chữ cái và chuyển về chữ hoa để tính shift
    clean_key = "".join(filter(str.isalpha, key)).upper()

    if not clean_key:
        return text

    for char in text:
        if char.isalpha():
            key_char = clean_key[key_index % len(clean_key)] # Đã sửa lỗi .length -> len()
            key_shift = ord(key_char) - ord('A')
            if char.islower():
                result += chr((ord(char) - ord('a') - key_shift + 26) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') - key_shift + 26) % 26 + ord('A'))
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


app = Flask(__name__)
# Đảm bảo CORS cho phép kết nối từ frontend của bạn. Nếu frontend chạy ở một cổng khác,
# bạn cần thêm 'http://localhost:port_frontend_của_bạn' vào danh sách origins.
CORS(app, origins=["http://localhost:5000"]) 
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    print("WARNING: SECRET_KEY environment variable not set. Using a temporary key for development.")
    app.secret_key = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///game.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Database Model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    score = db.Column(db.Integer, default=0)
    current_level = db.Column(db.Integer, default=1)
    attempts = db.relationship('UserAttempt', backref='user', lazy=True)

class UserAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    attempts_left = db.Column(db.Integer, default=5)
    last_attempt = db.Column(db.DateTime, nullable=True)

# Create database tables
with app.app_context():
    db.create_all()

LEVELS = [
    {
        "level": 1,
        "algorithm": "caesar",
        "ciphertext": "KhoiF, Zruog!", # Hello, World! with shift 3
        "correct_output": "Hello, World!",
        "hint": "Số bước dịch là số ngọn nến trong hang động (thử số nhỏ).",
        "story": "Bạn tìm thấy một mẩu giấy cổ trong hang động, ghi thông điệp bí ẩn dẫn đến kho báu.",
        "solution_param": 3
    },
    {
        "level": 2,
        "algorithm": "vigenere",
        "ciphertext": vigenere_cipher_encrypt("Hello, World!", "KEY"), # Mã hóa trước để đảm bảo
        "correct_output": "Hello, World!",
        "hint": "Từ khóa là tên của vị thần bảo vệ ngôi đền (3 chữ cái).",
        "story": "Thông điệp dẫn bạn đến ngôi đền cổ, nơi ẩn chứa câu đố phức tạp hơn.",
        "solution_param": "KEY"
    },
    {
        "level": 3,
        "algorithm": "rsa",
        "ciphertext": base64.b64encode(rsa_encrypt(rsa_public_key, "Find the key!")).decode(),
        "correct_output": "Find the key!",
        "hint": "Khóa riêng được khắc trên tường ngôi đền, cần định dạng đúng. (Gợi ý: Khóa RSA là một chuỗi dài, bắt đầu bằng '-----BEGIN RSA PRIVATE KEY-----')",
        "story": "Trong ngôi đền, bạn tìm thấy một chiếc hộp khóa bằng mật mã số học.",
        "solution_param": rsa_private_key.decode() # RSA private key in string format
    },
    {
        "level": 4,
        "algorithm": "aes",
        "ciphertext": base64.b64encode(aes_encrypt(aes_key, "You found the treasure!")).decode(),
        "correct_output": "You found the treasure!",
        "hint": "Khóa AES là mật khẩu cuối cùng, ẩn trong câu đố của chiếc hộp. (Gợi ý: Khóa AES là một chuỗi base64 ngắn gọn)",
        "story": "Chiếc hộp mở ra, tiết lộ vị trí kho báu, nhưng cần giải mã lần cuối!",
        "solution_param": base64.b64encode(aes_key).decode() # AES key in base64 string format
    }
]

@app.route('/register', methods=['POST'])
def register():
    """Đăng ký người dùng mới."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not username or not password or not confirm_password:
        return jsonify({"error": "Tên người dùng, mật khẩu và xác nhận mật khẩu không được để trống!"}), 400
    if password != confirm_password:
        return jsonify({"error": "Mật khẩu không khớp!"}), 400
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        return jsonify({"error": "Tên người dùng phải dài 3-20 ký tự, chỉ chứa chữ cái, số, dấu gạch dưới hoặc dấu gạch ngang!"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mật khẩu phải có ít nhất 6 ký tự!"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Tên người dùng đã tồn tại!"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"User registered: {username}")
    return jsonify({"message": "Đăng ký thành công!"}), 201

@app.route('/login', methods=['POST'])
def login():
    """Đăng nhập người dùng."""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        logger.warning(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Tên người dùng hoặc mật khẩu không đúng!"}), 401

    session['user_id'] = user.id
    session['username'] = user.username
    logger.info(f"User logged in: {username}")
    return jsonify({
        "message": "Đăng nhập thành công!",
        "username": user.username,
        "score": user.score,
        "current_level": user.current_level
    }), 200

@app.route('/logout', methods=['POST'])
def logout():
    """Đăng xuất người dùng."""
    username = session.get('username', 'Guest')
    session.pop('user_id', None)
    session.pop('username', None)
    logger.info(f"User logged out: {username}")
    return jsonify({"message": "Đăng xuất thành công!"}), 200

@app.route('/get_user_data', methods=['GET'])
def get_user_data():
    """Lấy thông tin người dùng."""
    if 'user_id' not in session:
        return jsonify({"error": "Chưa đăng nhập!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB but in session.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404
    return jsonify({
        "username": user.username,
        "score": user.score,
        "current_level": user.current_level
    }), 200

@app.route('/reset', methods=['POST'])
def reset_game():
    """Đặt lại trò chơi cho người dùng."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB during reset.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404
    user.score = 0
    user.current_level = 1
    UserAttempt.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    logger.info(f"Game reset for user: {user.username}")
    return jsonify({"message": "Trò chơi đã được đặt lại!", "score": 0, "current_level": 1}), 200

@app.route('/level/<int:level>', methods=['GET'])
def get_level(level):
    """Lấy thông tin cấp độ, kiểm tra quyền truy cập."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB when getting level.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404

    if level > user.current_level:
        return jsonify({"error": "Bạn chưa mở khóa cấp độ này!"}), 403
    if level < 1 or level > len(LEVELS):
        return jsonify({"error": "Cấp độ không hợp lệ!"}), 400

    level_data = LEVELS[level-1]
    attempt = UserAttempt.query.filter_by(user_id=user.id, level=level).first()
    attempts_left = 5 if not attempt else attempt.attempts_left
    return jsonify({
        "level": level_data["level"],
        "algorithm": level_data["algorithm"],
        "ciphertext": level_data["ciphertext"],
        "hint": level_data["hint"],
        "story": level_data["story"],
        "points": user.score,
        "current_user_level": user.current_level,
        "attempts_left": attempts_left
    })

@app.route('/decode/<int:level>', methods=['POST'])
def decode(level):
    """Xử lý giải mã thông điệp và cập nhật điểm số."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    if level < 1 or level > len(LEVELS):
        return jsonify({"error": "Cấp độ không hợp lệ!"}), 400

    data = request.json
    submitted_ciphertext = data.get('ciphertext')
    submitted_param = data.get('param')

    level_data = LEVELS[level-1]
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB during decode.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404

    if level > user.current_level:
        return jsonify({"error": "Bạn chưa mở khóa cấp độ này!"}), 403

    if submitted_ciphertext != level_data["ciphertext"]:
        return jsonify({"success": False, "message": "Thông điệp mã hóa không khớp với cấp độ hiện tại!", "attempts_left": UserAttempt.query.filter_by(user_id=user.id, level=level).first().attempts_left if UserAttempt.query.filter_by(user_id=user.id, level=level).first() else 5}), 400

    attempt = UserAttempt.query.filter_by(user_id=user.id, level=level).first()
    if not attempt:
        attempt = UserAttempt(user_id=user.id, level=level, attempts_left=5)
        db.session.add(attempt)
    if attempt.attempts_left <= 0:
        return jsonify({"success": False, "message": "Bạn đã hết số lần thử cho cấp độ này! Vui lòng đặt lại trò chơi."}), 403
    attempt.attempts_left -= 1
    attempt.last_attempt = datetime.utcnow()
    db.session.commit()

    try:
        decrypted_result = ""
        # solution_param = level_data["solution_param"] # Not needed directly for comparison here

        if level_data["algorithm"] == "caesar":
            if not submitted_param or not submitted_param.isdigit() or not (1 <= int(submitted_param) <= 25):
                return jsonify({"success": False, "message": "Độ dịch chuyển phải là số nguyên từ 1 đến 25!", "attempts_left": attempt.attempts_left}), 400
            decrypted_result = caesar_cipher_decrypt(submitted_ciphertext, int(submitted_param))
        elif level_data["algorithm"] == "vigenere":
            if not submitted_param or not re.match(r'^[a-zA-Z]+$', submitted_param):
                return jsonify({"success": False, "message": "Từ khóa chỉ được chứa chữ cái!", "attempts_left": attempt.attempts_left}), 400
            decrypted_result = vigenere_cipher_decrypt(submitted_ciphertext, submitted_param)
        elif level_data["algorithm"] == "rsa":
            if not submitted_param or not submitted_param.strip().startswith('-----BEGIN RSA PRIVATE KEY-----'):
                return jsonify({"success": False, "message": "Khóa RSA không hợp lệ. Phải bắt đầu bằng '-----BEGIN RSA PRIVATE KEY-----'!", "attempts_left": attempt.attempts_left}), 400
            try:
                # Mã hóa tin nhắn gốc với khóa công khai (rsa_encrypt) để tạo ciphertext ban đầu.
                # Sau đó, giải mã ciphertext được gửi từ người dùng với khóa riêng tư (rsa_decrypt).
                # Vì mục đích trò chơi, `submitted_ciphertext` đã là kết quả của `rsa_encrypt` với đúng khóa công khai.
                # Do đó, chúng ta chỉ cần giải mã `submitted_ciphertext` bằng `submitted_param` (khóa riêng của người dùng).
                encrypted_message_bytes = base64.b64decode(submitted_ciphertext)
                decrypted_result = rsa_decrypt(submitted_param.encode(), encrypted_message_bytes)
            except Exception as e:
                logger.error(f"RSA decryption error for user {user.username} at level {level}: {e}")
                return jsonify({"success": False, "message": f"Khóa RSA không hợp lệ: {str(e)}", "attempts_left": attempt.attempts_left}), 400
        elif level_data["algorithm"] == "aes":
            if not submitted_param:
                return jsonify({"success": False, "message": "Khóa AES không được để trống!", "attempts_left": attempt.attempts_left}), 400
            try:
                aes_key_bytes_from_param = base64.b64decode(submitted_param)
                if len(aes_key_bytes_from_param) != 16:
                    return jsonify({"success": False, "message": "Khóa AES phải là 16 byte sau khi giải mã base64!", "attempts_left": attempt.attempts_left}), 400
                iv_and_ciphertext_bytes = base64.b64decode(submitted_ciphertext)
                decrypted_result = aes_decrypt(aes_key_bytes_from_param, iv_and_ciphertext_bytes)
            except Exception as e:
                logger.error(f"AES decryption error for user {user.username} at level {level}: {e}")
                return jsonify({"success": False, "message": f"Khóa AES không hợp lệ: {str(e)}", "attempts_left": attempt.attempts_left}), 400
        else:
            return jsonify({"success": False, "message": "Thuật toán không hỗ trợ!", "attempts_left": attempt.attempts_left}), 400

        if decrypted_result == level_data["correct_output"]:
            points_earned = 100 * level
            user.score += points_earned
            if level == user.current_level:
                user.current_level = level + 1 if level < len(LEVELS) else level
            attempt.attempts_left = 5  # Reset attempts on success
            db.session.commit()
            logger.info(f"User {user.username} successfully decoded level {level}. Score: {user.score}")
            return jsonify({
                "success": True,
                "message": f"Thông điệp đã được giải mã thành công! Kết quả: {decrypted_result}",
                "points_earned": points_earned,
                "total_points": user.score,
                "next_level": user.current_level if user.current_level > level else None,
                "attempts_left": attempt.attempts_left
            })
        else:
            logger.info(f"User {user.username} failed to decode level {level}. Incorrect output.")
            return jsonify({
                "success": False,
                "message": f"Giải mã không chính xác. Còn {attempt.attempts_left} lần thử!",
                "attempts_left": attempt.attempts_left
            })
    except Exception as e:
        logger.error(f"Unhandled decryption error for user {user.username} at level {level}: {e}", exc_info=True)
        return jsonify({"success": False, "message": f"Lỗi hệ thống: {str(e)}", "attempts_left": attempt.attempts_left}), 500

# --- GEMINI API INTEGRATION ---
@app.route('/gemini/hint', methods=['POST'])
def gemini_hint():
    """
    Endpoint API để lấy gợi ý từ LLM Gemini.
    Nhận: JSON body với các trường 'cipherType' và 'encodedMessage'.
    Trả về: JSON object với 'hint' từ Gemini hoặc 'error' message.
    """
    data = request.json
    cipher_type = data.get('cipherType')
    encoded_message = data.get('encodedMessage')

    if not cipher_type or not encoded_message:
        return jsonify({'error': 'Thiếu loại mật mã hoặc tin nhắn mã hóa để lấy gợi ý.'}), 400

    # Xây dựng prompt cho Gemini dựa trên loại mật mã
    prompt = ""
    if cipher_type == 'caesar':
        prompt = f"Tôi đang chơi một trò chơi giải mã. Mật mã hiện tại là Caesar Cipher và tin nhắn mã hóa là '{encoded_message}'. Hãy cho tôi một gợi ý tinh tế về cách tìm 'độ dịch chuyển' mà không tiết lộ trực tiếp đáp án. Gợi ý phải bằng tiếng Việt và chỉ tập trung vào gợi ý."
    elif cipher_type == 'vigenere':
        prompt = f"Tôi đang chơi một trò chơi giải mã. Mật mã hiện tại là Vigenère Cipher và tin nhắn mã hóa là '{encoded_message}'. Hãy cho tôi một gợi ý tinh tế về cách tìm 'từ khóa' mà không tiết lộ trực tiếp đáp án. Gợi ý phải bằng tiếng Việt và chỉ tập trung vào gợi ý."
    elif cipher_type == 'rsa':
        prompt = f"Tôi đang chơi một trò chơi giải mã. Mật mã hiện tại là RSA. Hãy cho tôi một gợi ý tinh tế về cách tìm 'khóa riêng' mà không tiết lộ trực tiếp đáp án. Gợi ý phải bằng tiếng Việt và chỉ tập trung vào gợi ý."
    elif cipher_type == 'aes':
        prompt = f"Tôi đang chơi một trò chơi giải mã. Mật mã hiện tại là AES. Hãy cho tôi một gợi ý tinh tế về cách tìm 'khóa AES' mà không tiết lộ trực tiếp đáp án. Gợi ý phải bằng tiếng Việt và chỉ tập trung vào gợi ý."
    else:
        return jsonify({'error': 'Loại mật mã không hợp lệ để lấy gợi ý.'}), 400

    try:
        # Cấu hình payload cho API Gemini
        chat_history = [{"role": "user", "parts": [{"text": prompt}]}]
        payload = {"contents": chat_history}
        api_key = "" # GIỮ RỖNG: Canvas sẽ tự động cung cấp API key khi chạy
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

        headers = {'Content-Type': 'application/json'}
        # Gửi yêu cầu đến API Gemini
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status() # Nâng ngoại lệ cho các lỗi HTTP (4xx hoặc 5xx)
        
        gemini_result = response.json()
        
        # Trích xuất gợi ý từ phản hồi của Gemini
        if gemini_result and gemini_result.get('candidates') and len(gemini_result['candidates']) > 0 and \
           gemini_result['candidates'][0].get('content') and gemini_result['candidates'][0]['content'].get('parts') and \
           len(gemini_result['candidates'][0]['content']['parts']) > 0:
            hint = gemini_result['candidates'][0]['content']['parts'][0]['text']
        else:
            hint = "Không thể tạo gợi ý lúc này. Phản hồi từ Gemini không như mong đợi."

        return jsonify({'hint': hint})

    except requests.exceptions.RequestException as e:
        # Xử lý lỗi liên quan đến kết nối mạng hoặc phản hồi từ API Gemini
        print(f"Lỗi khi gọi API Gemini: {e}")
        return jsonify({'error': f'Lỗi kết nối API Gemini: {str(e)}. Vui lòng đảm bảo bạn có kết nối internet.'}), 500
    except Exception as e:
        # Xử lý các lỗi khác
        print(f"Lỗi nội bộ server khi xử lý Gemini hint: {e}")
        return jsonify({'error': f'Lỗi nội bộ server khi lấy gợi ý: {str(e)}'}), 500

@app.route('/')
def index():
    """Render giao diện chính."""
    return render_template('index.html')

if __name__ == '__main__':
    # Thông báo cho người dùng biết server đang chạy ở đâu và các đáp án câu đố
    print(f"Flask Backend Server đang chạy trên: http://127.0.0.1:5000/")
    print(f"Hãy đảm bảo Frontend của bạn (index.html) đang gọi API đến địa chỉ này.")
    print(f"\n--- Đáp án cho các cấp độ câu đố (được nhập vào frontend) ---")
    # In ra đáp án thực tế từ các biến đã được khởi tạo
    print(f"Caesar Cipher: Shift là {LEVELS[0]['solution_param']} (dùng để kiểm tra)")
    print(f"Vigenère Cipher: Key là '{LEVELS[1]['solution_param']}' (dùng để kiểm tra)")
    print(f"RSA Puzzle (Cấp độ 3): Nhập khóa riêng: '{LEVELS[2]['solution_param']}'")
    print(f"AES Puzzle (Cấp độ 4): Nhập khóa AES: '{LEVELS[3]['solution_param']}'")
    
    # Chạy ứng dụng Flask ở chế độ debug (tự động tải lại khi có thay đổi)
    # và lắng nghe trên cổng 5000.
    app.run(debug=True, port=5000)

# Import các hàm mã hóa và khóa từ module mới
from MultipleFiles.cipher_utils import (
    caesar_cipher_decrypt,
    vigenere_cipher_decrypt,
    rsa_decrypt,
    aes_decrypt,
    rsa_encrypt,
    aes_encrypt,
    rsa_public_key,
    rsa_private_key,
    generate_and_save_keys
)

app = Flask(__name__)
CORS(app, origins=["http://localhost:5000"])
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    print("WARNING: SECRET_KEY environment variable not set. Using a temporary key for development.")
    app.secret_key = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///game.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lấy khóa AES từ biến môi trường
AES_KEY = base64.b64decode(os.getenv('AES_KEY', base64.b64encode(os.urandom(16)).decode()))
if len(AES_KEY) != 16:
    raise ValueError("AES_KEY phải là chuỗi base64 đại diện cho khóa 16 byte!")

# Database Model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    score = db.Column(db.Integer, default=0)
    current_level = db.Column(db.Integer, default=1)
    attempts = db.relationship('UserAttempt', backref='user', lazy=True)

class UserAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    attempts_left = db.Column(db.Integer, default=5)
    last_attempt = db.Column(db.DateTime, nullable=True)

# Create database tables
with app.app_context():
    db.create_all()

LEVELS = [
    {
        "level": 1,
        "algorithm": "caesar",
        "ciphertext": "KhoiF, Zruog!",
        "correct_output": "Hello, World!",
        "hint": "Số bước dịch là số ngọn nến trong hang động (thử số nhỏ).",
        "story": "Bạn tìm thấy một mẩu giấy cổ trong hang động, ghi thông điệp bí ẩn dẫn đến kho báu.",
        "solution_param": 3
    },
    {
        "level": 2,
        "algorithm": "vigenere",
        "ciphertext": "Rijvs, Uyvzr!",
        "correct_output": "Hello, World!",
        "hint": "Từ khóa là tên của vị thần bảo vệ ngôi đền (3 chữ cái).",
        "story": "Thông điệp dẫn bạn đến ngôi đền cổ, nơi ẩn chứa câu đố phức tạp hơn.",
        "solution_param": "KEY"
    },
    {
        "level": 3,
        "algorithm": "rsa",
        "ciphertext": base64.b64encode(rsa_encrypt(rsa_public_key, "Find the key!")).decode(),
        "correct_output": "Find the key!",
        "hint": "Khóa riêng được khắc trên tường ngôi đền, cần định dạng đúng. (Gợi ý: Khóa RSA là một chuỗi dài, bắt đầu bằng '-----BEGIN RSA PRIVATE KEY-----')",
        "story": "Trong ngôi đền, bạn tìm thấy một chiếc hộp khóa bằng mật mã số học.",
        "solution_param": rsa_private_key.decode()
    },
    {
        "level": 4,
        "algorithm": "aes",
        "ciphertext": base64.b64encode(aes_encrypt(AES_KEY, "You found the treasure!")).decode(),
        "correct_output": "You found the treasure!",
        "hint": "Khóa AES là mật khẩu cuối cùng, ẩn trong câu đố của chiếc hộp. (Gợi ý: Khóa AES là một chuỗi base64 ngắn gọn)",
        "story": "Chiếc hộp mở ra, tiết lộ vị trí kho báu, nhưng cần giải mã lần cuối!",
        "solution_param": base64.b64encode(AES_KEY).decode()
    }
]

@app.route('/register', methods=['POST'])
def register():
    """Đăng ký người dùng mới."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not username or not password or not confirm_password:
        return jsonify({"error": "Tên người dùng, mật khẩu và xác nhận mật khẩu không được để trống!"}), 400
    if password != confirm_password:
        return jsonify({"error": "Mật khẩu không khớp!"}), 400
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        return jsonify({"error": "Tên người dùng phải dài 3-20 ký tự, chỉ chứa chữ cái, số, dấu gạch dưới hoặc dấu gạch ngang!"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mật khẩu phải có ít nhất 6 ký tự!"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Tên người dùng đã tồn tại!"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"User registered: {username}")
    return jsonify({"message": "Đăng ký thành công!"}), 201

@app.route('/login', methods=['POST'])
def login():
    """Đăng nhập người dùng."""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        logger.warning(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Tên người dùng hoặc mật khẩu không đúng!"}), 401

    session['user_id'] = user.id
    session['username'] = user.username
    logger.info(f"User logged in: {username}")
    return jsonify({
        "message": "Đăng nhập thành công!",
        "username": user.username,
        "score": user.score,
        "current_level": user.current_level
    }), 200

@app.route('/logout', methods=['POST'])
def logout():
    """Đăng xuất người dùng."""
    username = session.get('username', 'Guest')
    session.pop('user_id', None)
    session.pop('username', None)
    logger.info(f"User logged out: {username}")
    return jsonify({"message": "Đăng xuất thành công!"}), 200

@app.route('/get_user_data', methods=['GET'])
def get_user_data():
    """Lấy thông tin người dùng."""
    if 'user_id' not in session:
        return jsonify({"error": "Chưa đăng nhập!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB but in session.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404
    return jsonify({
        "username": user.username,
        "score": user.score,
        "current_level": user.current_level
    }), 200

@app.route('/reset', methods=['POST'])
def reset_game():
    """Đặt lại trò chơi cho người dùng."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB during reset.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404
    user.score = 0
    user.current_level = 1
    UserAttempt.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    logger.info(f"Game reset for user: {user.username}")
    return jsonify({"message": "Trò chơi đã được đặt lại!", "score": 0, "current_level": 1}), 200

@app.route('/level/<int:level>', methods=['GET'])
def get_level(level):
    """Lấy thông tin cấp độ, kiểm tra quyền truy cập."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB when getting level.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404

    if level > user.current_level:
        return jsonify({"error": "Bạn chưa mở khóa cấp độ này!"}), 403
    if level < 1 or level > len(LEVELS):
        return jsonify({"error": "Cấp độ không hợp lệ!"}), 400

    level_data = LEVELS[level-1]
    attempt = UserAttempt.query.filter_by(user_id=user.id, level=level).first()
    attempts_left = 5 if not attempt else attempt.attempts_left
    return jsonify({
        "level": level_data["level"],
        "algorithm": level_data["algorithm"],
        "ciphertext": level_data["ciphertext"],
        "hint": level_data["hint"],
        "story": level_data["story"],
        "points": user.score,
        "current_user_level": user.current_level,
        "attempts_left": attempts_left
    })

@app.route('/decode/<int:level>', methods=['POST'])
def decode(level):
    """Xử lý giải mã thông điệp và cập nhật điểm số."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    if level < 1 or level > len(LEVELS):
        return jsonify({"error": "Cấp độ không hợp lệ!"}), 400

    data = request.json
    submitted_ciphertext = data.get('ciphertext')
    submitted_param = data.get('param')

    level_data = LEVELS[level-1]
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB during decode.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404

    if level > user.current_level:
        return jsonify({"error": "Bạn chưa mở khóa cấp độ này!"}), 403

    if submitted_ciphertext != level_data["ciphertext"]:
        return jsonify({"success": False, "message": "Thông điệp mã hóa không khớp với cấp độ hiện tại!"}), 400

    attempt = UserAttempt.query.filter_by(user_id=user.id, level=level).first()
    if not attempt:
        attempt = UserAttempt(user_id=user.id, level=level, attempts_left=5)
        db.session.add(attempt)
    if attempt.attempts_left <= 0:
        return jsonify({"success": False, "message": "Bạn đã hết số lần thử cho cấp độ này! Vui lòng đặt lại trò chơi."}), 403
    attempt.attempts_left -= 1
    attempt.last_attempt = datetime.utcnow()
    db.session.commit()

    try:
        decrypted_result = ""
        solution_param = level_data["solution_param"]

        if level_data["algorithm"] == "caesar":
            if not submitted_param or not submitted_param.isdigit() or not (1 <= int(submitted_param) <= 25):
                return jsonify({"success": False, "message": "Độ dịch chuyển phải là số nguyên từ 1 đến 25!", "attempts_left": attempt.attempts_left}), 400
            decrypted_result = caesar_cipher_decrypt(submitted_ciphertext, int(submitted_param))
        elif level_data["algorithm"] == "vigenere":
            if not submitted_param or not re.match(r'^[a-zA-Z]+$', submitted_param):
                return jsonify({"success": False, "message": "Từ khóa chỉ được chứa chữ cái!", "attempts_left": attempt.attempts_left}), 400
            decrypted_result = vigenere_cipher_decrypt(submitted_ciphertext, submitted_param)
        elif level_data["algorithm"] == "rsa":
            if not submitted_param or not submitted_param.strip().startswith('-----BEGIN RSA PRIVATE KEY-----'):
                return jsonify({"success": False, "message": "Khóa RSA không hợp lệ. Phải bắt đầu bằng '-----BEGIN RSA PRIVATE KEY-----'!", "attempts_left": attempt.attempts_left}), 400
            try:
                encrypted_message_bytes = base64.b64decode(submitted_ciphertext)
                decrypted_result = rsa_decrypt(submitted_param.encode(), encrypted_message_bytes)
            except Exception as e:
                logger.error(f"RSA decryption error for user {user.username} at level {level}: {e}")
                return jsonify({"success": False, "message": f"Khóa RSA không hợp lệ: {str(e)}", "attempts_left": attempt.attempts_left}), 400
        elif level_data["algorithm"] == "aes":
            if not submitted_param:
                return jsonify({"success": False, "message": "Khóa AES không được để trống!", "attempts_left": attempt.attempts_left}), 400
            try:
                aes_key_bytes_from_param = base64.b64decode(submitted_param)
                if len(aes_key_bytes_from_param) != 16:
                    return jsonify({"success": False, "message": "Khóa AES phải là 16 byte sau khi giải mã base64!", "attempts_left": attempt.attempts_left}), 400
                iv_and_ciphertext_bytes = base64.b64decode(submitted_ciphertext)
                decrypted_result = aes_decrypt(aes_key_bytes_from_param, iv_and_ciphertext_bytes)
            except Exception as e:
                logger.error(f"AES decryption error for user {user.username} at level {level}: {e}")
                return jsonify({"success": False, "message": f"Khóa AES không hợp lệ: {str(e)}", "attempts_left": attempt.attempts_left}), 400
        else:
            return jsonify({"success": False, "message": "Thuật toán không hỗ trợ!", "attempts_left": attempt.attempts_left}), 400

        if decrypted_result == level_data["correct_output"]:
            points_earned = 100 * level
            user.score += points_earned
            if level == user.current_level:
                user.current_level = level + 1 if level < len(LEVELS) else level
            attempt.attempts_left = 5  # Reset attempts on success
            db.session.commit()
            logger.info(f"User {user.username} successfully decoded level {level}. Score: {user.score}")
            return jsonify({
                "success": True,
                "message": f"Thông điệp đã được giải mã thành công! Kết quả: {decrypted_result}",
                "points_earned": points_earned,
                "total_points": user.score,
                "next_level": user.current_level if user.current_level > level else None,
                "attempts_left": attempt.attempts_left
            })
        else:
            logger.info(f"User {user.username} failed to decode level {level}. Incorrect output.")
            return jsonify({
                "success": False,
                "message": f"Giải mã không chính xác. Còn {attempt.attempts_left} lần thử!",
                "attempts_left": attempt.attempts_left
            })
    except Exception as e:
        logger.error(f"Unhandled decryption error for user {user.username} at level {level}: {e}", exc_info=True)
        return jsonify({"success": False, "message": f"Lỗi hệ thống: {str(e)}", "attempts_left": attempt.attempts_left}), 500

@app.route('/')
def index():
    """Render giao diện chính."""
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)