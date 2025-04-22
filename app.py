import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import pyotp
import qrcode
from io import BytesIO
import base64
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder='templates')
app.secret_key = 'SUA_CHAVE_MUITO_SECRETA_AQUI_123!@#'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    secret_2fa = db.Column(db.String(32))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('verify_2fa'))
        flash('Email ou senha inválidos!', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email já registrado!', 'danger')
            return redirect(url_for('register'))
        
        secret_2fa = pyotp.random_base32()
        hashed_pw = generate_password_hash(password)
        
        # Gera QR Code
        uri = pyotp.totp.TOTP(secret_2fa).provisioning_uri(email, issuer_name="MeuApp")
        img = qrcode.make(uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        new_user = User(email=email, password=hashed_pw, secret_2fa=secret_2fa)
        db.session.add(new_user)
        db.session.commit()
        
        return render_template('register.html', 
                           qrcode_img=img_str,
                           secret_2fa=secret_2fa)
    
    return render_template('register.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    # Verifica se o usuário está autenticado e tem secret_2fa
    if not current_user.is_authenticated or not hasattr(current_user, 'secret_2fa'):
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))

    secret = current_user.secret_2fa

    if request.method == 'POST':
        user_code = request.form.get('code', '').strip()
        
        if not user_code:
            flash('Digite o código 2FA', 'danger')
        else:
            totp = pyotp.TOTP(secret)
            if totp.verify(user_code, valid_window=1):
                session['2fa_passed'] = True  # ← Agora usando session corretamente
                return redirect(url_for('dashboard'))
            flash('Código 2FA inválido', 'danger')

    return render_template('verify_2fa.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('2fa_passed'):  # ← Agora session está definido
        flash('Complete a verificação 2FA primeiro', 'warning')
        return redirect(url_for('verify_2fa'))
    
    return render_template('dashboard.html')
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
