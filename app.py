from flask import Flask, render_template, redirect, request, url_for, flash, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
from models import db, User
import os
from models import File
import hashlib
from utils import decrypt_file
import io
from io import BytesIO

# ---------------- Flask App Setup ---------------- #
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- Master Key Loading ---------------- #
# Load or create master key if not present
MASTER_KEY_FILE = "master.key"
if not os.path.exists(MASTER_KEY_FILE):
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(MASTER_KEY_FILE, "rb") as f:
    master_key = f.read()

master_fernet = Fernet(master_key)

#Error Handler for large files
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash("File too large. Max allowed size is 10MB.")
    return redirect(request.url)

# ---------------- Routes ---------------- #

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        # Generate and encrypt user-specific Fernet key
        user_key = Fernet.generate_key()
        encrypted_user_key = master_fernet.encrypt(user_key)

        # Store user info
        new_user = User(
            email=email,
            password=password,
            encrypted_user_key=encrypted_user_key.decode()
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed.')
    return render_template('login.html')

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', files=files)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Upload route
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')

        # 1. Check if no file was selected
        if not file or file.filename == '':
            flash('No file selected.')
            return redirect(request.url)

        # 2. Check for unsupported file types
        if not allowed_file(file.filename):
            flash('File type not allowed. Please upload only supported file types.')
            return redirect(request.url)

        # 3. (Optional) Check file size limit (e.g., max 10MB)
        max_size = 10 * 1024 * 1024  # 10 MB
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)  # Reset pointer to read from start again

        if file_length > max_size:
            flash('File size exceeds the 10MB limit.')
            return redirect(request.url)

        # 4. Proceed with encryption and saving
        original_filename = secure_filename(file.filename)
        stored_filename = original_filename + '.enc'

        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
        os.makedirs(user_folder, exist_ok=True)

        file_data = file.read()

        encrypted_user_key = current_user.encrypted_user_key.encode()
        with open('master.key', 'rb') as key_file:
            master_key = key_file.read()
        master_fernet = Fernet(master_key)
        user_key = master_fernet.decrypt(encrypted_user_key)
        user_fernet = Fernet(user_key)

        encrypted_data = user_fernet.encrypt(file_data)
        file_hash = hashlib.sha256(file_data).hexdigest()

        encrypted_path = os.path.join(user_folder, stored_filename)
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        # Save file metadata in database
        new_file = File(
            user_id=current_user.id,
            filename=original_filename,
            stored_filename=stored_filename,
            file_path=encrypted_path,
            file_hash=file_hash
        )
        db.session.add(new_file)
        db.session.commit()

        flash('File uploaded, encrypted, and saved successfully.')
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

# Download route
@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)

    if file_record.user_id != current_user.id:
        flash("Unauthorized access.")
        return redirect(url_for('dashboard'))

    from utils import decrypt_file
    encrypted_user_key = current_user.encrypted_user_key.encode()

    try:
        decrypted_data = decrypt_file(
            file_path=file_record.file_path,
            encrypted_user_key=encrypted_user_key,
            master_key_path='master.key'
        )
    except InvalidToken:
        flash("Decryption failed! The file may have been tampered with or corrupted.")
        return redirect(url_for('dashboard'))

    from flask import send_file
    from io import BytesIO
    return send_file(BytesIO(decrypted_data),
                     download_name=file_record.filename,
                     as_attachment=True,
                     mimetype='application/octet-stream')

#Verify Route
@app.route('/verify')
@login_required
def verify():
    return render_template('verify.html')

#Landing Page Route
@app.route('/')
def home():
    return render_template('index.html')

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)