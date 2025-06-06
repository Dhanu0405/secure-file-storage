from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User

from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os

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

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welcome, {current_user.email}!"

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

        if not file or file.filename == '':
            flash('No file selected.')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('File type not allowed.')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
        os.makedirs(user_folder, exist_ok=True)

        # Get encrypted key from current user and decrypt it
        encrypted_key = current_user.encrypted_user_key.encode()
        user_fernet_key = master_fernet.decrypt(encrypted_key)
        user_fernet = Fernet(user_fernet_key)

        # Encrypt file and save
        file_data = file.read()
        encrypted_data = user_fernet.encrypt(file_data)

        encrypted_path = os.path.join(user_folder, filename + '.enc')
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        flash('Encrypted file uploaded successfully.')
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/')
def home():
    return render_template('index.html')

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)