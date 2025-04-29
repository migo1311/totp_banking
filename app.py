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
import base64
import hashlib
import hmac
import os
import struct
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import random

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = os.urandom(24)

_enhanced_counter = 0

class TOTPGmailSender:
    def __init__(self, gmail_user, gmail_password, default_recipient, totp_secret=None):
        """
        Initialize the TOTP Gmail Sender with enhanced TOTP algorithm
        
        Args:
            gmail_user (str): Gmail username/email
            gmail_password (str): Gmail password or app password
            default_recipient (str): Default email to send OTPs to
            totp_secret (str, optional): TOTP secret key. If None, a new one is generated.
        """
        self.gmail_user = gmail_user
        self.gmail_password = gmail_password
        self.default_recipient = default_recipient
        self.interval = 30  # Time interval in seconds
        
        # Generate or use provided TOTP secret
        self.totp_secret = totp_secret if totp_secret else self.generate_random_base32()
        
        # Cache for current TOTP code
        self.current_code = None
        self.current_interval = 0  # Track the current interval number
    
    def generate_random_base32(self, length=32):
        """
        Generate a random base32 encoded secret key
        
        Args:
            length (int): Length of the secret key in bytes before encoding
            
        Returns:
            str: Base32 encoded secret key
        """
        # Generate random bytes
        random_bytes = os.urandom(length)
        
        # Use SHA-512 to process the random bytes
        hashed_bytes = hashlib.sha512(random_bytes).digest()
        
        # Encode as base32 and return as string
        return base64.b32encode(hashed_bytes[:length]).decode('utf-8')
    
    def generate_totp(self):
        """
        Generate a new enhanced TOTP code, with caching to prevent code changes
        on repeated calls within the same time window
        
        Returns:
            str: 6-digit TOTP code
        """
        # Calculate current interval number
        current_interval = self.current_interval
        
        # Only generate a new code if we don't have one or the interval has changed
        if (self.current_code is None or 
            current_interval > self.current_interval):
            
            self.current_code = self.get_enhanced_totp(self.totp_secret, current_interval)
            self.current_interval = current_interval
            
        return self.current_code
    
    def get_totp_expiry(self):
        """
        Get seconds until current TOTP expires
        
        Returns:
            float: Seconds until expiry
        """
        return self.interval
    
    def verify_totp(self, code):
        """
        Verify if the provided TOTP code is valid
        
        Args:
            code (str): TOTP code to verify
            
        Returns:
            bool: True if code is valid, False otherwise
        """
        # Get the current valid code (using the cached value)
        current_code = self.generate_totp()
        
        # Direct comparison with the current code
        if code == current_code:
            return True
        
        return False
    
    def get_enhanced_totp(self, input_data, interval_number):
        """
        Enhanced TOTP algorithm with improved collision resistance
        
        Args:
            input_data (str): Base32 encoded secret key
            interval_number (int): The current interval number
            
        Returns:
            str: 6-digit TOTP code
        """
        global _enhanced_counter
        
        # Increment the counter for each code generation
        _enhanced_counter += 1
        
        # Create a more complex input by using HMAC to combine components
        # First, prepare the counter bytes using interval number instead of time
        counter_bytes = struct.pack('>Q', interval_number)
        
        # Decode the input data if it's base32 encoded
        try:
            key = base64.b32decode(input_data, casefold=True)
        except:
            # If not base32, use as is
            key = input_data.encode()
        
        # Add counter component to the key
        enhanced_key = key + struct.pack('>Q', _enhanced_counter)
        
        # Use HMAC-SHA512 instead of plain SHA512
        hmac_hash = hmac.new(enhanced_key, counter_bytes, hashlib.sha512).digest()
        
        # Create a pseudorandom mapping for extraction positions instead of sequential extraction
        # Use part of the hash itself to determine extraction positions
        hash_len = len(hmac_hash)
        
        # Create a list of all possible positions
        all_positions = list(range(hash_len))
        
        # Shuffle the positions based on bytes from the hmac_hash itself
        # This creates a deterministic but non-sequential extraction pattern
        extraction_positions = []
        for i in range(6):  # We need 6 positions for a 6-digit OTP
            # Use different parts of the hash to influence the selection
            # This creates a pseudo-random but deterministic selection
            seed_value = (hmac_hash[i] << 24 | 
                        hmac_hash[i+6] << 16 | 
                        hmac_hash[i+12] << 8 | 
                        hmac_hash[i+18])
            
            # Use the seed to select a position from remaining positions
            position_index = seed_value % len(all_positions)
            extraction_positions.append(all_positions.pop(position_index))
        
        # Extract values from the hash at the determined positions
        digits = []
        for pos in extraction_positions:
            # Use modulo 10 to get a decimal digit from any position in the hash
            digit = hmac_hash[pos] % 10
            digits.append(digit)
        
        # Combine all digits to form the OTP
        otp = 0
        for i, digit in enumerate(digits):
            otp += digit * (10 ** (5 - i))
        
        return '{:06d}'.format(otp)

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

    def run_replay_attack_test(self, time_windows=30, num_simulations=5, verification_window=1, time_drift_seconds=5):
        # Store the original interval
        original_interval = self.current_interval
        
        try:
            # Run multiple simulations
            all_simulation_results = []
            all_success_windows = []
            first_initial_code = None
            
            for sim in range(num_simulations):
                # Generate the initial valid TOTP code at the current interval
                base_interval = self.current_interval
                
                # Apply random interval drift to simulate clock synchronization issues
                drift = random.randint(-1, 1)  # Drift in intervals
                drifted_interval = base_interval + drift
                
                # Set the interval for initial code generation
                self.current_interval = drifted_interval
                initial_code = self.generate_totp()
                
                # Store the first simulation's code
                if sim == 0:
                    first_initial_code = initial_code
                
                # Try to use this code in future intervals
                success_windows = []
                
                # For each future window, check if the initial code is still valid
                for window in range(1, time_windows + 1):
                    future_interval = base_interval + window
                    
                    # For each window, check codes within the verification window
                    for v in range(-verification_window, verification_window + 1):
                        adjusted_interval = future_interval + v
                        
                        # Set the interval for this check
                        self.current_interval = adjusted_interval
                        window_code = self.generate_totp()
                        
                        if initial_code == window_code:
                            success_windows.append(window)
                            break  # Found a match, no need to check other verification windows
                
                # Store results of this simulation
                all_simulation_results.append({
                    "simulation": sim + 1,
                    "initial_code": initial_code,
                    "success_windows": success_windows,
                    "success_rate": len(success_windows) / time_windows,
                    "applied_drift": drift
                })
                
                # Collect all success windows for aggregate calculation
                all_success_windows.extend(success_windows)
            
            # Calculate aggregate statistics
            avg_success_rate = sum(sim["success_rate"] for sim in all_simulation_results) / len(all_simulation_results)
            unique_success_windows = sorted(list(set(all_success_windows)))
            
            # Return results
            return {
                "initial_code": first_initial_code,
                "success_windows": unique_success_windows,
                "success_rate": avg_success_rate,
                "simulations": all_simulation_results,
                "avg_success_rate": avg_success_rate,
                "unique_vulnerable_windows": unique_success_windows,
                "total_vulnerable_windows": len(unique_success_windows),
                "num_simulations": num_simulations
            }
            
        finally:
            # Always restore the original interval
            self.current_interval = original_interval

    def run_brute_force_test(self, attempts=None):
        """
        Simulate a brute-force attack on TOTP
        Returns the found code or None if unsuccessful
        """ 
        # Get the target code from the enhanced TOTP implementation
        # Use the same interval number that was used when sending the email
        target_code = self.current_code  # Use the cached code instead of generating a new one
        
        # List to store all attempted codes
        attempted_codes = []
        
        # Start timing
        start_time = time.time()
        
        # Try random codes until we find the correct one
        attempt = 0
        while True:
            random_code = ''.join(random.choices('0123456789', k=6))
            attempted_codes.append(random_code)
            attempt += 1
            
            if random_code == target_code:
                # Calculate time taken
                end_time = time.time()
                time_taken = end_time - start_time
                
                # Return successful code with all attempts and timing info
                return {
                    'found_code': random_code,
                    'attempts': attempt,
                    'attempted_codes': attempted_codes,
                    'time_taken': time_taken
                }
            
            # If attempts limit is specified and reached, stop
            if attempts is not None and attempt >= attempts:
                # Calculate time taken
                end_time = time.time()
                time_taken = end_time - start_time
                
                # No successful match found within attempts
                return {
                    'found_code': None,
                    'attempts': attempts,
                    'attempted_codes': attempted_codes,
                    'time_taken': time_taken
                }

        
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
            # Failure case - include the correct code for demonstration/debugging
            correct_code = totp_sender.generate_totp()  # Get the current correct TOTP
            return jsonify({
                "valid": False, 
                "message": "Invalid OTP", 
                "correct_code": correct_code  # Include the correct code
            })
    
    # GET request - just show the form
    return render_template('verify.html')

@app.route('/run_brute_force_test', methods=['POST'])
def run_brute_force_test():
    try:
        print("Received brute force test request")  # Debug log
        data = request.get_json()
        attempts = data.get('attempts', None)  # Default to None (unlimited attempts)
        print(f"Attempts parameter: {attempts}")  # Debug log
        
        # Run the brute force test
        result = totp_sender.run_brute_force_test(attempts)
        print(f"Brute force test result: {result}")  # Debug log
        
        # Add additional information to the result
        result['last_attempted_code'] = totp_sender.generate_totp()  # Get the current valid code
        
        return jsonify(result)
    except Exception as e:
        print(f"Error in brute force test: {str(e)}")  # Debug log
        return jsonify({
            'error': str(e),
            'message': 'An error occurred during the brute force test'
        }), 500

# Main
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
