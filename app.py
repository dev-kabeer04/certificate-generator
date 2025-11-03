from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import qrcode
import sqlite3
import os
from datetime import datetime
import io
import csv

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database setup
def init_db():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Certificates table
    c.execute('''CREATE TABLE IF NOT EXISTS certificates
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  certificate_id TEXT UNIQUE NOT NULL,
                  name TEXT NOT NULL,
                  course_name TEXT NOT NULL,
                  issue_date TEXT NOT NULL,
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (created_by) REFERENCES users(id))''')
    
    # Create default admin if not exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_pass = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('admin', admin_pass, 'admin'))
    
    conn.commit()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2])
    return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('certificates.db')
        c = conn.cursor()
        c.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            user_obj = User(user[0], user[1], user[3])
            login_user(user_obj)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    
    if current_user.role == 'admin':
        c.execute("SELECT COUNT(*) FROM certificates")
        total_certs = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0]
    else:
        c.execute("SELECT COUNT(*) FROM certificates WHERE created_by = ?", (current_user.id,))
        total_certs = c.fetchone()[0]
        total_users = 0
    
    conn.close()
    
    return render_template('dashboard.html', total_certs=total_certs, total_users=total_users)

@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    if request.method == 'POST':
        course_name = request.form['course_name']
        issue_date = request.form['issue_date']
        names_input = request.form['names']
        
        # Parse names (either CSV upload or text input)
        names = [name.strip() for name in names_input.split('\n') if name.strip()]
        
        conn = sqlite3.connect('certificates.db')
        c = conn.cursor()
        
        generated_count = 0
        for name in names:
            cert_id = f"CERT-{datetime.now().strftime('%Y%m%d')}-{generated_count + 1:04d}"
            
            try:
                c.execute('''INSERT INTO certificates 
                            (certificate_id, name, course_name, issue_date, created_by)
                            VALUES (?, ?, ?, ?, ?)''',
                         (cert_id, name, course_name, issue_date, current_user.id))
                generated_count += 1
            except sqlite3.IntegrityError:
                continue
        
        conn.commit()
        conn.close()
        
        flash(f'Successfully generated {generated_count} certificates!', 'success')
        return redirect(url_for('view_certificates'))
    
    return render_template('generate.html')

@app.route('/certificates')
@login_required
def view_certificates():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    
    if current_user.role == 'admin':
        c.execute('''SELECT c.id, c.certificate_id, c.name, c.course_name, c.issue_date, c.created_at
                     FROM certificates c ORDER BY c.created_at DESC''')
    else:
        c.execute('''SELECT c.id, c.certificate_id, c.name, c.course_name, c.issue_date, c.created_at
                     FROM certificates c WHERE c.created_by = ? ORDER BY c.created_at DESC''',
                 (current_user.id,))
    
    certificates = c.fetchall()
    conn.close()
    
    return render_template('certificates.html', certificates=certificates)

@app.route('/download/<cert_id>')
@login_required
def download_certificate(cert_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute('''SELECT certificate_id, name, course_name, issue_date 
                 FROM certificates WHERE certificate_id = ?''', (cert_id,))
    cert = c.fetchone()
    conn.close()
    
    if not cert:
        flash('Certificate not found', 'error')
        return redirect(url_for('view_certificates'))
    
    # Generate PDF
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=landscape(letter))
    width, height = landscape(letter)
    
    # Background
    c.setFillColorRGB(0.95, 0.95, 1)
    c.rect(0, 0, width, height, fill=True, stroke=False)
    
    # Border
    c.setStrokeColorRGB(0.2, 0.2, 0.6)
    c.setLineWidth(3)
    c.rect(30, 30, width-60, height-60, fill=False, stroke=True)
    
    # Title
    c.setFillColorRGB(0.1, 0.1, 0.5)
    c.setFont("Helvetica-Bold", 40)
    c.drawCentredString(width/2, height-100, "CERTIFICATE OF COMPLETION")
    
    # Divider
    c.setStrokeColorRGB(0.7, 0.7, 0.7)
    c.line(150, height-130, width-150, height-130)
    
    # Name
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 16)
    c.drawCentredString(width/2, height-180, "This is to certify that")
    
    c.setFillColorRGB(0.1, 0.1, 0.5)
    c.setFont("Helvetica-Bold", 32)
    c.drawCentredString(width/2, height-230, cert[1])
    
    # Course details
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 16)
    c.drawCentredString(width/2, height-280, "has successfully completed the course")
    
    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(width/2, height-320, cert[2])
    
    # Date
    c.setFont("Helvetica", 14)
    c.drawCentredString(width/2, height-370, f"Date of Completion: {cert[3]}")
    
    # QR Code
    verify_url = f"http://localhost:5000/verify/{cert[0]}"
    qr = qrcode.QRCode(version=1, box_size=3, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)
    
    c.drawImage(ImageReader(qr_buffer), 50, 50, width=80, height=80)
    c.setFont("Helvetica", 8)
    c.drawString(50, 35, "Scan to verify")
    
    # Signature line
    c.setStrokeColorRGB(0, 0, 0)
    c.line(width-250, 100, width-100, 100)
    c.setFont("Helvetica", 12)
    c.drawCentredString(width-175, 80, "Authorized Signature")
    
    # Certificate ID
    c.setFont("Helvetica", 8)
    c.drawString(width-200, 35, f"Certificate ID: {cert[0]}")
    
    c.save()
    pdf_buffer.seek(0)
    
    return send_file(pdf_buffer, as_attachment=True, 
                    download_name=f"certificate_{cert[0]}.pdf",
                    mimetype='application/pdf')

@app.route('/verify/<cert_id>')
def verify_certificate(cert_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute('''SELECT certificate_id, name, course_name, issue_date 
                 FROM certificates WHERE certificate_id = ?''', (cert_id,))
    cert = c.fetchone()
    conn.close()
    
    if cert:
        return render_template('verify.html', cert={
            'id': cert[0],
            'name': cert[1],
            'course': cert[2],
            'date': cert[3],
            'valid': True
        })
    else:
        return render_template('verify.html', cert={'valid': False})

@app.route('/users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at FROM users")
    users = c.fetchall()
    conn.close()
    
    return render_template('users.html', users=users)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    
    try:
        hashed_password = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                 (username, hashed_password, role))
        conn.commit()
        flash(f'User {username} added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists', 'error')
    
    conn.close()
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)