import os
import io
import sys
import time
from flask import send_file
from flask import Flask, session, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_bcrypt import Bcrypt
from flask_session import Session
from database import Base,Accounts,Customers,Users,CustomerLog,Transactions
from sqlalchemy import create_engine, exc
from sqlalchemy.orm import scoped_session, sessionmaker
import datetime
import xlwt
import pyotp
from fpdf import FPDF
from sqlalchemy import text
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = os.urandom(24)

class TOTPGmailSender:
    def __init__(self, gmail_user, gmail_password, default_recipient, totp_secret=None):
        """
        Initialize the TOTP Gmail Sender
        
        Args:
            gmail_user (str): Gmail username/email
            gmail_password (str): Gmail password or app password
            default_recipient (str): Default email to send OTPs to
            totp_secret (str, optional): TOTP secret key. If None, a new one is generated.
        """
        self.gmail_user = gmail_user
        self.gmail_password = gmail_password
        self.default_recipient = default_recipient
        
        # Generate or use provided TOTP secret
        self.totp_secret = totp_secret if totp_secret else pyotp.random_base32()
        self.totp = pyotp.TOTP(self.totp_secret)
    
    def generate_totp(self):
        """Generate a new TOTP code"""
        return self.totp.now()
    
    def get_totp_expiry(self):
        """Get seconds until current TOTP expires"""
        return 30 - datetime.now().timestamp() % 30
    
    def verify_totp(self, code):
        """Verify if the provided TOTP code is valid"""
        return self.totp.verify(code)
    
    def send_totp_email(self, subject="Your OTP Code"):
        """
        Generate and send a TOTP code via Gmail to the default recipient
        
        Args:
            subject (str): Email subject
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            totp_code = self.generate_totp()
            expiry_seconds = self.get_totp_expiry()
            
            # Create email
            msg = MIMEMultipart()
            msg['From'] = self.gmail_user
            msg['To'] = self.default_recipient
            msg['Subject'] = subject
            
            # Email body
            body = f"""
            <html>
              <body>
                <h2>Your One-Time Password (OTP)</h2>
                <p>Your verification code is: <strong style="font-size: 24px;">{totp_code}</strong></p>
                <p>This code will expire in {int(expiry_seconds)} seconds.</p>
                <p>If you did not request this code, please ignore this email.</p>
              </body>
            </html>
            """
            msg.attach(MIMEText(body, 'html'))
            
            # Connect to Gmail
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.login(self.gmail_user, self.gmail_password)
            
            # Send email
            server.send_message(msg)
            server.quit()
            
            print(f"TOTP code sent to {self.default_recipient}")
            return True
            
        except Exception as e:
            print(f"Error sending TOTP email: {e}")
            return False

# Set up database
engine = create_engine('sqlite:///database.db',connect_args={'check_same_thread': False},echo=True)
Base.metadata.bind = engine
db = scoped_session(sessionmaker(bind=engine))
    
# MAIN
@app.route('/')
@app.route("/dashboard")
def dashboard():
    return render_template("home.html", home=True)

@app.route("/storeshop" , methods=["GET", "POST"])
def storeshop():
    if 'user' not in session:
        return redirect(url_for('login'))        
    if session['usert']=="executive" or session['usert']=="teller" or session['usert']=="cashier":
        if request.method == "POST":
            acc_id = request.form.get("acc_id")
            cust_id = request.form.get("cust_id")
            sql_query = text("SELECT * from accounts WHERE cust_id = :c or acc_id = :d")
            data = db.execute(sql_query, {"c": cust_id, "d": acc_id}).fetchall()
            if data:
                return render_template('storeshop.html', storeshop=True, data=data)
            
            flash("Account not found! Please,Check you input.", 'danger')
    else:
        flash("You don't have access to this page","warning")
        return redirect(url_for('dashboard'))
    return render_template('storeshop.html', storeshop=True)

# route for 404 error
@app.errorhandler(404)
def not_found(e):
  return render_template("404.html") 

# Logout 
@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        usern = request.form.get("username").upper()
        passw = request.form.get("password").encode('utf-8')
        sql_query = text('SELECT * FROM users WHERE id = :u')
        #result = db.execute(sql_query, {"u": usern}).fetchone()
        result = db.query(Users).filter_by(id=usern).first()
        if result is not None:
            if bcrypt.check_password_hash(result.password, passw) is True:
                session['user'] = usern
                session['namet'] = result.name
                session['usert'] = result.user_type
                flash(f"{result.name.capitalize()}, you are successfully logged in!", "success")
                return redirect(url_for('dashboard'))
        flash("Sorry, Username or password not match.","danger")
    return render_template("login.html", login=True)

@app.route('/confirm_purchase', methods=['POST'])
def confirm_purchase():
    return render_template('confirm_purchase.html')

@app.route('/TOTP', methods=['POST'])
def TOTP():
    return render_template('TOTP.html')

totp = pyotp.TOTP(app.secret_key)
    
# Initialize TOTP sender
GMAIL_USER = os.environ.get("GMAIL_USER")
GMAIL_PASSWORD = os.environ.get("GMAIL_PASSWORD")
DEFAULT_RECIPIENT = os.environ.get("DEFAULT_RECIPIENT")


# Check if credentials are available
if not GMAIL_USER or not GMAIL_PASSWORD:
    print("WARNING: Gmail credentials not found in environment variables.")
    print("Set GMAIL_USER and GMAIL_PASSWORD environment variables.")
    # For development only - remove in production:
    GMAIL_USER = "josephmiguel326@gmail.com"  # Replace with your email in development
    GMAIL_PASSWORD = "sdkc ttfq huck rdna"  # Replace with your password in development
    DEFAULT_RECIPIENT = "josephmiguel326@gmail.com"

# Initialize the TOTP sender
gmail_user = os.environ.get("GMAIL_USER")
gmail_password = os.environ.get("GMAIL_PASSWORD")
totp_sender = TOTPGmailSender(GMAIL_USER, GMAIL_PASSWORD, DEFAULT_RECIPIENT)

@app.route('/send-totp', methods=['POST'])
def send_totp():
    # Send TOTP email to the default recipient
    if totp_sender.send_totp_email():
        flash('TOTP code sent to the default email account')
        return redirect(url_for('verify_code'))
    else:
        flash('Failed to send TOTP code. Please try again.')
        return redirect(url_for('index'))

@app.route('/verify', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        totp_code = request.form.get('totp_code')
        
        if totp_sender.verify_totp(totp_code):
            # Success case
            return jsonify({"valid": True, "message": "Verification successful!"})
        else:
            # Failure case
            return jsonify({"valid": False, "message": "Invalid OTP"})
    
    # GET request - just show the form
    return render_template('verify.html')

# Main
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
