from flask import Flask, render_template, request, send_file, url_for, redirect, flash, jsonify
import os
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFont
import pandas as pd
import time
import zipfile
import io
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'idgenerator'
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'png', 'jpeg', 'jpg'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate

app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    email_verified = db.Column(db.Boolean, default=False)
    unique_id = db.Column(db.String(13), nullable=False, unique=True)  # Add this line

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    email = StringField(validators=[InputRequired(), Email(), Length(min=4, max=120)], render_kw={"placeholder": "Email"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError('That email already exists. Please choose a different one.')

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirmation-salt')

def send_verification_email(user):
    token = generate_confirmation_token(user.email)
    verify_url = url_for('confirm_email', token=token, _external=True)
    msg = Message('Confirm Your Email', sender='noreply@example.com', recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{verify_url}
If you did not make this request, please ignore this email.
'''
    mail.send(msg)

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('id_card_generator.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('id_card_generator'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        unique_id = generate_unique_id()
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, unique_id=unique_id)
        db.session.add(new_user)
        db.session.commit()
        send_verification_email(new_user)
        flash('A verification email has been sent to your email address. Please check your inbox.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

def generate_unique_id():
    # Generate a unique ID (for simplicity, using current timestamp)
    return str(int(time.time() * 1000))

def justify_text(draw, text, position, width, font, fill_color, justification="left"):
    font_width, font_height = draw.textsize(text, font)
    text_width = font.getsize(text)[0]

    if justification == "left":
        x = position[0]
    elif justification == "center":
        x = position[0] + (width - text_width) // 2
    elif justification == "right":
        x = position[0] + (width - text_width)
    else:
        raise ValueError("Invalid justification. Use 'left', 'center', or 'right'.")

    y = position[1]
    draw.text((x, y), text, font=font, fill=fill_color)

def generate_id_card(row, template_path, zip_file):
    template = Image.open(template_path)
    draw = ImageDraw.Draw(template)
    font_path = "C:/Windows/Fonts/Calibri.ttf"
     
    name_font_size = 70
    portfolio_font_size = 50
    
    name_font = ImageFont.truetype(font_path, name_font_size)
    portfolio_font = ImageFont.truetype(font_path, portfolio_font_size)

    # Get name and portfolio from the row
    name = row['Name']
    portfolio = row['portfolio']

    # Generate unique ID
    unique_id = generate_unique_id()

    # Draw name and portfolio
    x_name = (template.size[0] - 400) // 2 
    y_name = 970
    name_width = 400  

    x_portfolio = (template.size[0] - 400) // 2  
    y_portfolio = 1070
    portfolio_width = 400  

    justify_text(draw, name, (x_name, y_name), name_width, name_font, "white", justification="center")
    justify_text(draw, portfolio, (x_portfolio, y_portfolio), portfolio_width, portfolio_font, "white", justification="center")

    img_buffer = io.BytesIO()
    template.save(img_buffer, format="PNG")
    img_buffer.seek(0)

    zip_info = zipfile.ZipInfo(f"id_card_{unique_id}.png")
    zip_info.date_time = time.localtime(time.time())[:6]
    zip_info.compress_type = zipfile.ZIP_DEFLATED
    zip_file.writestr(zip_info, img_buffer.getvalue())

@app.route('/id_card_generator', methods=['GET', 'POST'])
def id_card_generator():
    if request.method == 'POST':
        if 'csvFile' not in request.files or 'templateImage' not in request.files:
            return render_template('id_card_generator.html', message='Missing file parts')

        csv_file = request.files['csvFile']
        template_image = request.files['templateImage']

        if csv_file.filename == '' or template_image.filename == '':
            return render_template('id_card_generator.html', message='Please select both files')

        if allowed_file(csv_file.filename) and allowed_file(template_image.filename):
            csv_filename = secure_filename(csv_file.filename)
            template_filename = secure_filename(template_image.filename)

            csv_path = os.path.join(app.config['UPLOAD_FOLDER'], csv_filename)
            template_path = os.path.join(app.config['UPLOAD_FOLDER'], template_filename)

            csv_file.save(csv_path)
            template_image.save(template_path)

            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                df = pd.read_csv(csv_path)
                for index, row in df.iterrows():
                    generate_id_card(row, template_path, zip_file)

            zip_buffer.seek(0)
            return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='id_cards.zip')
        else:
            return render_template('id_card_generator.html', message='Invalid file type. Please upload a CSV and a PNG file.')

    return render_template('id_card_generator.html', message='Upload a CSV and a PNG file')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_verified:
        flash('Account already verified. Please log in.', 'success')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Your account has been verified. Please log in.', 'success')
    return redirect(url_for('login'))

@app.route('/verify_id', methods=['POST'])
def verify_id():
    data = request.get_json()
    unique_id = data.get('unique_id')

    if not unique_id:
        return jsonify({'status': 'error', 'message': 'Unique ID is required'}), 400

    user = User.query.filter_by(unique_id=unique_id).first()

    if user:
        return jsonify({'status': 'success', 'message': 'ID verified', 'user': user.username, 'portfolio': user.portfolio}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid ID'}), 404

if __name__ == '__main__':
    app.run(debug=True)

