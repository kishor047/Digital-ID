import streamlit as st
import csv
import qrcode
from PIL import Image, ImageDraw, ImageFont
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random
import hashlib
import time
import re
import hmac
from dotenv import load_dotenv

# ─────────────────────────────────────────────
# Load credentials from .env file (NEVER hardcode)
# Create a .env file with:
#   EMAIL_ADDRESS=your_email@gmail.com
#   EMAIL_PASSWORD=your_app_password
# ─────────────────────────────────────────────
load_dotenv()
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
OTP_EXPIRY_SECONDS = 300        # OTP valid for 5 minutes
MAX_OTP_ATTEMPTS   = 3          # Max wrong attempts before lockout
MAX_EMAIL_REQUESTS = 3          # Max OTP sends per session
ALLOWED_DOMAINS    = [          # Add any domain you want to allow
    "gmail.com", "yahoo.com", "outlook.com",
    "hotmail.com", "vcet.edu.in"
]


# ─────────────────────────────────────────────
# Session State Initialization
# ─────────────────────────────────────────────
def init_session():
    defaults = {
        "otp_hash":        None,
        "otp_timestamp":   None,
        "otp_attempts":    0,
        "email_requests":  0,
        "verified":        False,
        "locked":          False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# ─────────────────────────────────────────────
# Input Validation
# ─────────────────────────────────────────────
def is_valid_student_id(student_id: str) -> bool:
    """Only allow positive integers."""
    return student_id.strip().isdigit() and int(student_id.strip()) > 0


def is_valid_email(email: str) -> bool:
    """Check format and allowed domain."""
    pattern = r'^[\w\.\+\-]+@[\w\-]+\.[\w\.]+$'
    if not re.match(pattern, email):
        return False
    domain = email.strip().lower().split("@")[-1]
    return domain in ALLOWED_DOMAINS


# ─────────────────────────────────────────────
# OTP Utilities
# ─────────────────────────────────────────────
def generate_otp() -> str:
    """Generate a 6-digit secure OTP."""
    return str(random.SystemRandom().randint(100000, 999999))


def hash_otp(otp: str) -> str:
    """Hash OTP using SHA-256 — never store plain text OTP."""
    return hashlib.sha256(otp.encode()).hexdigest()


def store_otp_in_session(otp: str):
    """Store hashed OTP and timestamp in session (not in any file)."""
    st.session_state["otp_hash"]      = hash_otp(otp)
    st.session_state["otp_timestamp"] = time.time()
    st.session_state["otp_attempts"]  = 0


def verify_otp(user_otp: str) -> tuple[bool, str]:
    """
    Returns (success: bool, message: str)
    Checks: lockout → expiry → attempt limit → hash match
    """
    if st.session_state["locked"]:
        return False, "⛔ Too many wrong attempts. Session locked."

    if not st.session_state["otp_hash"]:
        return False, "❌ No OTP found. Please request a new one."

    # Check expiry
    elapsed = time.time() - st.session_state["otp_timestamp"]
    if elapsed > OTP_EXPIRY_SECONDS:
        st.session_state["otp_hash"] = None
        return False, f"⏰ OTP expired after {OTP_EXPIRY_SECONDS // 60} minutes. Request a new one."

    # Check attempt limit
    if st.session_state["otp_attempts"] >= MAX_OTP_ATTEMPTS:
        st.session_state["locked"] = True
        return False, "⛔ Too many wrong attempts. Session locked for security."

    # Constant-time comparison to prevent timing attacks
    input_hash    = hash_otp(user_otp.strip())
    stored_hash   = st.session_state["otp_hash"]
    is_match      = hmac.compare_digest(input_hash, stored_hash)

    if is_match:
        st.session_state["verified"]   = True
        st.session_state["otp_hash"]   = None   # Invalidate after use
        return True, "✅ OTP verified successfully!"
    else:
        st.session_state["otp_attempts"] += 1
        remaining = MAX_OTP_ATTEMPTS - st.session_state["otp_attempts"]
        return False, f"❌ Wrong OTP. {remaining} attempt(s) remaining."


# ─────────────────────────────────────────────
# Email Sending
# ─────────────────────────────────────────────
def send_verification_email(email: str, otp: str) -> tuple[bool, str]:
    """Send OTP email with full error handling."""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return False, "Server email credentials are not configured. Contact admin."

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
        server.ehlo()
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

        msg              = MIMEMultipart()
        msg["From"]      = EMAIL_ADDRESS
        msg["To"]        = email
        msg["Subject"]   = "Your ID Card Verification Code"

        body = (
            f"Your verification code is: {otp}\n\n"
            f"This code is valid for {OTP_EXPIRY_SECONDS // 60} minutes.\n"
            f"Do not share this code with anyone.\n\n"
            f"If you did not request this, please ignore this email."
        )
        msg.attach(MIMEText(body, "plain"))
        server.send_message(msg)
        server.quit()
        return True, "✅ Verification email sent successfully."

    except smtplib.SMTPAuthenticationError:
        return False, "Email authentication failed. Check server credentials."
    except smtplib.SMTPConnectError:
        return False, "Could not connect to email server. Check internet connection."
    except smtplib.SMTPRecipientsRefused:
        return False, f"Email address '{email}' was rejected by the server."
    except TimeoutError:
        return False, "Email server connection timed out. Try again."
    except Exception as e:
        return False, f"Unexpected error sending email: {str(e)}"


# ─────────────────────────────────────────────
# CSV Data Fetching
# ─────────────────────────────────────────────
def fetch_student_info(student_id: int) -> dict | None:
    """Safely fetch student record from CSV."""
    csv_path = "student.csv"

    if not os.path.exists(csv_path):
        st.error("Student database file not found. Contact admin.")
        return None

    try:
        with open(csv_path, "r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get("stuid", "").strip() == str(student_id):
                    return row
        return None

    except PermissionError:
        st.error("Permission denied reading student database.")
        return None
    except csv.Error as e:
        st.error(f"CSV file is corrupted or malformed: {e}")
        return None
    except Exception as e:
        st.error(f"Unexpected error reading student data: {e}")
        return None


# ─────────────────────────────────────────────
# ID Card Generator
# ─────────────────────────────────────────────
def generate_digital_id(student_info: dict) -> str | None:
    """Generate ID card image with QR code."""
    try:
        student_id  = student_info.get("stuid", "unknown")
        output_dir  = "generated_ids"
        os.makedirs(output_dir, exist_ok=True)

        image = Image.new("RGB", (1000, 900), (255, 255, 255))
        draw  = ImageDraw.Draw(image)

        try:
            font = ImageFont.truetype("arial.ttf", 24)
        except IOError:
            font = ImageFont.load_default()

        # Draw fields
        fields = [
            (50,  50,  student_info.get("college",    "Unknown College")),
            (50,  150, f"Student ID : {student_id}"),
            (50,  250, f"Name       : {student_info.get('name',       'Unknown')}"),
            (50,  350, f"Gender     : {student_info.get('gender',     'Unknown')}"),
            (50,  450, f"DOB        : {student_info.get('dob',        'Unknown')}"),
            (50,  550, f"Blood Group: {student_info.get('bloodgroup', 'Unknown')}"),
        ]
        for x, y, text in fields:
            color = (200, 0, 0) if "Blood" in text else (0, 0, 0)
            draw.text((x, y), text, fill=color, font=font)

        # QR Code — encode student ID only (no PII)
        qr = qrcode.QRCode(version=1, box_size=8, border=4)
        qr.add_data(f"STUDENT_ID:{student_id}")
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        image.paste(qr_img, (620, 350))

        output_path = os.path.join(output_dir, f"{student_id}_id.png")
        image.save(output_path)
        return output_path

    except Exception as e:
        st.error(f"Error generating ID card: {e}")
        return None


# ─────────────────────────────────────────────
# Main App
# ─────────────────────────────────────────────
def main():
    st.set_page_config(page_title="Digital ID Generator", page_icon="🪪")
    init_session()

    st.title("🪪 Digital ID Card Generator")
    st.caption("All fields are mandatory. Enter details carefully.")

    # Show lockout banner
    if st.session_state["locked"]:
        st.error("⛔ Session locked due to too many failed attempts. Please refresh the page.")
        st.stop()

    # ── Step 1: Student ID Input ──────────────────
    st.subheader("Step 1 — Enter Student ID")
    student_id_input = st.text_input("Student ID", placeholder="e.g. 12345", max_chars=10)

    if st.button("Send Verification Code"):

        # Rate limit OTP requests
        if st.session_state["email_requests"] >= MAX_EMAIL_REQUESTS:
            st.error("⛔ Maximum OTP requests reached. Please refresh the page.")
            st.stop()

        # Validate Student ID format
        if not student_id_input or not is_valid_student_id(student_id_input):
            st.error("❌ Invalid Student ID. Please enter a positive number.")
            st.stop()

        student_info = fetch_student_info(int(student_id_input))
        if not student_info:
            st.error("❌ No student found with this ID.")
            st.stop()

        email = student_info.get("email", "").strip()

        # Validate email format and domain
        if not email:
            st.error("❌ No email found for this student.")
            st.stop()

        if not is_valid_email(email):
            allowed = ", ".join(ALLOWED_DOMAINS)
            st.error(
                f"❌ Email domain not supported.\n\n"
                f"Allowed domains: **{allowed}**\n\n"
                f"Found email: `{email}`"
            )
            st.stop()

        # Generate and send OTP
        otp     = generate_otp()
        success, message = send_verification_email(email, otp)

        if success:
            store_otp_in_session(otp)
            st.session_state["email_requests"] += 1
            # Show masked email for privacy
            masked = email[:2] + "****@" + email.split("@")[-1]
            st.success(f"✅ OTP sent to **{masked}**. Valid for 5 minutes.")
        else:
            st.error(f"❌ {message}")

    # ── Step 2: OTP Verification ──────────────────
    st.subheader("Step 2 — Enter Verification Code")
    otp_input = st.text_input("Verification Code", placeholder="6-digit code", max_chars=6)

    if st.button("Verify & Generate ID"):

        if not otp_input.strip():
            st.error("❌ Please enter the verification code.")
            st.stop()

        if not is_valid_student_id(student_id_input):
            st.error("❌ Please enter a valid Student ID first.")
            st.stop()

        success, message = verify_otp(otp_input)
        st.info(message)

        if success:
            student_info = fetch_student_info(int(student_id_input))
            if not student_info:
                st.error("❌ Student data not found.")
                st.stop()

            with st.spinner("Generating your ID card..."):
                id_file = generate_digital_id(student_info)

            if id_file:
                st.success("✅ ID Card generated!")
                id_image = Image.open(id_file)
                st.image(id_image, caption="Your Digital ID", use_column_width=True)

                with open(id_file, "rb") as f:
                    st.download_button(
                        label="⬇️ Download ID Card",
                        data=f,
                        file_name=os.path.basename(id_file),
                        mime="image/png"
                    )
            else:
                st.error("❌ Failed to generate ID card.")


if __name__ == "__main__":
    main()
