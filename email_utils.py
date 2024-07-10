from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from flask import url_for, current_app

# Generate the token
s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

def generate_confirmation_token(email):
    return s.dumps(email, salt='email-confirmation-salt')

def send_verification_email(user):
    token = generate_confirmation_token(user.email)
    verify_url = url_for('confirm_email', token=token, _external=True)
    msg = Message('Confirm Your Email', sender='noreply@example.com', recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{verify_url}
If you did not make this request, please ignore this email.
'''
    mail.send(msg)
