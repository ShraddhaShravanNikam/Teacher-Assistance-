
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import random
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename


from flask import session



app = Flask(__name__)
app.secret_key = 'your_very_secure_key_here'

# Database configuration

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'  # Store session on disk

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to User table
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Auto-set time

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'

# Create tables
with app.app_context():
    db.create_all()

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Admin Registration Flow
@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Admin username already exists', 'danger')
            return redirect(url_for('admin_register'))
        
        hashed_password = generate_password_hash(password)
        new_admin = User(
            username=username,
            password=hashed_password,
            role='admin'  # Explicitly set role to admin
        )
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin registration successful! Please login', 'success')
        return redirect(url_for('admin_login'))  # Redirect to ADMIN login
    return render_template('admin_register.html')

# Admin Login Route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if user exists and is an admin
        user = User.query.filter_by(username=username, role='admin').first()
        
        if user and check_password_hash(user.password, password):
            # Set session variables
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            # Flash success message
            flash('Login successful! Welcome back, Admin.', 'success')
            
            # Redirect to admin dashboard
            return redirect(url_for('admin_dashboard'))
        
        # If authentication fails
        flash('Invalid admin credentials. Please try again.', 'danger')
    
    return render_template('admin_login.html')

# Admin Dashboard Route
@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if user is logged in and is an admin
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Please login as admin to access this page', 'warning')
        return redirect(url_for('admin_login'))
    
    # Render dashboard with username
    return render_template('admin_dashboard.html', 
                         username=session.get('username'))

# User Routes (Separate from admin flow)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, role='user').first()  # Only allow users
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('user_dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session or session.get('role') != 'user':
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    return render_template('user_dashboard.html', username=session.get('username'))


@app.route('/notification')
def notification():
    if 'user_id' not in session or session.get('role') != 'user':
        flash('Please login first', 'warning')
        return redirect(url_for('login'))  # Redirect to login page
    
    user_id = session.get('user_id')
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.timestamp.desc()).all()

    return render_template('notification.html', username=session.get('username'), notifications=notifications)

@app.route('/profile')
def profile():
    if 'user_id' not in session or session.get('role') != 'user':
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    # Fetch user details from the database
    user = User.query.filter_by(id=session['user_id']).first()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('user_dashboard'))
    
    return render_template('profile.html', user=user)


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session or session.get('role') != 'user':
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')

        # Check if username already exists (except for the current user)
        existing_user = User.query.filter(User.username == new_username, User.id != user.id).first()
        if existing_user:
            flash('Username already taken! Choose a different one.', 'danger')
            return redirect(url_for('edit_profile'))

        user.username = new_username

        # Update password only if provided
        if new_password:
            user.password = generate_password_hash(new_password)

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))  # Redirect back to the profile page

    return render_template('edit_profile.html', user=user)

@app.route('/mathematics')
def mathematics_page():
    if 'user_id' not in session or session.get('role') != 'user':
        flash('Please login first', 'warning')
        return redirect(url_for('login'))
    
    # Fetch assignments from database (if implemented)
    assignments = [
        {"title": "Algebra Worksheet", "due_date": "2025-04-05"},
        {"title": "Geometry Quiz", "due_date": "2025-04-10"},
        {"title": "Trigonometry Practice", "due_date": "2025-04-15"},
    ]

    return render_template('mathematics.html', assignments=assignments)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}  # Allowed file types

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def analyze_assignment(file_path):
    """Fake AI-based analysis: Generates random marks and a suggestion."""
    marks = random.randint(50, 100)  # Assign random marks (50-100)
    suggestions = "Improve clarity and add more examples." if marks < 80 else "Great job! Keep up the good work."
    return marks, suggestions

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'assignment' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)

        file = request.files['assignment']

        if file.filename == '':
            flash('No file selected', 'warning')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # AI analysis
            marks, suggestions = analyze_assignment(file_path)

            # Store result in session
            session['last_result'] = {'marks': marks, 'suggestions': suggestions}
            session.modified = True  # Ensure session updates

            print("\n=== DEBUG: Session Data After Upload ===")
            print(session.get('last_result'))  # Debugging
            print("====================================\n")

            return redirect(url_for('result'))  

    return render_template('upload.html')

@app.route('/science')
def science_page():
    assignments = []  # Fetch assignments from DB if needed
    return render_template('science.html', assignments=assignments)

@app.route('/result')
def result():
    last_result = session.get('last_result', {'marks': 'N/A', 'suggestions': 'N/A'})
    
    print("\n=== DEBUG: Session Data in /result ===")
    print(last_result)
    print("====================================\n")

    return render_template('result.html', marks=last_result['marks'], suggestions=last_result['suggestions'])

@app.route('/notifications')
def notifications():
    last_result = session.get('last_result', None)

    print("\n=== DEBUG: Session Data in /notifications ===")
    print(last_result)
    print("====================================\n")

    return render_template('notification.html', result=last_result)


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)