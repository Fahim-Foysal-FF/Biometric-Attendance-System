import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from datetime import datetime, timedelta
import time
from flask_mail import Mail, Message
import re
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.hash import sha256_crypt
import secrets
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import psycopg2
from psycopg2.extras import DictCursor

app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# PostgreSQL configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
mail = Mail(app)

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize serializer
s = URLSafeTimedSerializer(app.secret_key)

# Database models
class User(db.Model):
    __tablename__ = 'userss'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.String(50))
    is_approved = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100))
    mobile_number = db.Column(db.String(20))
    department = db.Column(db.String(100))
    designation = db.Column(db.String(100))
    roll_number = db.Column(db.String(50))
    session = db.Column(db.String(50))
    semester = db.Column(db.String(20))
    photo = db.Column(db.String(200))
    reg_no = db.Column(db.String(50))
    father_name = db.Column(db.String(100))
    mother_name = db.Column(db.String(100))
    present_address = db.Column(db.Text)
    permanent_address = db.Column(db.Text)
    dob = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Student(db.Model):
    __tablename__ = 'student'
    id = db.Column(db.Integer, primary_key=True)
    roll_number = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    mobile_number = db.Column(db.String(20))
    user_type = db.Column(db.String(50))
    session = db.Column(db.String(50))
    password = db.Column(db.String(200))
    department = db.Column(db.String(100))
    semester = db.Column(db.String(20))
    reg_no = db.Column(db.String(50))
    father_name = db.Column(db.String(100))
    mother_name = db.Column(db.String(100))
    present_address = db.Column(db.Text)
    permanent_address = db.Column(db.Text)
    dob = db.Column(db.Date)

class Teacher(db.Model):
    __tablename__ = 'teacher'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    mobile_number = db.Column(db.String(20))
    user_type = db.Column(db.String(50))
    password = db.Column(db.String(200))
    department = db.Column(db.String(100))
    designation = db.Column(db.String(100))
    present_address = db.Column(db.Text)
    permanent_address = db.Column(db.Text)
    dob = db.Column(db.Date)

class Chairman(db.Model):
    __tablename__ = 'chairman'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    mobile_number = db.Column(db.String(20))
    user_type = db.Column(db.String(50))
    password = db.Column(db.String(200))
    department = db.Column(db.String(100))
    designation = db.Column(db.String(100))
    present_address = db.Column(db.Text)
    permanent_address = db.Column(db.Text)
    dob = db.Column(db.Date)

class Staff(db.Model):
    __tablename__ = 'staff'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    mobile_number = db.Column(db.String(20))
    user_type = db.Column(db.String(50))
    password = db.Column(db.String(200))
    department = db.Column(db.String(100))
    designation = db.Column(db.String(100))
    present_address = db.Column(db.Text)
    permanent_address = db.Column(db.Text)
    dob = db.Column(db.Date)

class Course(db.Model):
    __tablename__ = 'course'
    id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(50), unique=True)
    course_name = db.Column(db.String(100))
    department = db.Column(db.String(100))
    semester = db.Column(db.String(20))

class StudentCourseAssign(db.Model):
    __tablename__ = 'student_course_assign'
    id = db.Column(db.Integer, primary_key=True)
    roll_number = db.Column(db.String(50))
    session = db.Column(db.String(50))
    semester = db.Column(db.String(20))
    course_code = db.Column(db.String(50))
    course_name = db.Column(db.String(100))
    department = db.Column(db.String(100))

class TeacherCourseAssign(db.Model):
    __tablename__ = 'teacher_course_assign'
    id = db.Column(db.Integer, primary_key=True)
    teacher_name = db.Column(db.String(100))
    department = db.Column(db.String(100))
    session = db.Column(db.String(50))
    semester = db.Column(db.String(20))
    course_code = db.Column(db.String(50))
    course_name = db.Column(db.String(100))
    email = db.Column(db.String(120))

class Result(db.Model):
    __tablename__ = 'result'
    id = db.Column(db.Integer, primary_key=True)
    roll_number = db.Column(db.String(50))
    session = db.Column(db.String(50))
    semester = db.Column(db.String(20))
    course_code = db.Column(db.String(50))
    exam_type = db.Column(db.String(50))
    marks = db.Column(db.Float)

class Classes(db.Model):
    __tablename__ = 'classes'
    id = db.Column(db.Integer, primary_key=True)
    session = db.Column(db.String(50))
    semester = db.Column(db.String(20))
    course_code = db.Column(db.String(50))
    class_date = db.Column(db.Date)
    start_time = db.Column(db.Time)
    end_time = db.Column(db.Time)

class UsersLogs(db.Model):
    __tablename__ = 'users_logs'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    serialnumber = db.Column(db.String(50))
    device_uid = db.Column(db.String(100))
    checkindate = db.Column(db.Date)
    timein = db.Column(db.Time)
    timeout = db.Column(db.Time)
    fingerout = db.Column(db.Integer)

class Notices(db.Model):
    __tablename__ = 'notices'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    posted_by = db.Column(db.String(100))
    date = db.Column(db.Date)
    file_url = db.Column(db.String(200))

class CourseFeedback(db.Model):
    __tablename__ = 'course_feedback'
    id = db.Column(db.Integer, primary_key=True)
    roll_number = db.Column(db.String(50))
    course_code = db.Column(db.String(50))
    rating = db.Column(db.Integer)
    comment = db.Column(db.Text)

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def execute_query(query, params=None, fetch=False):
    try:
        # Handle params as a dictionary for SQLAlchemy compatibility
        if params is None:
            param_dict = {}
        elif isinstance(params, dict):
            param_dict = params
        elif isinstance(params, tuple):
            # Convert tuple to dictionary with numbered placeholders
            param_dict = {str(i + 1): val for i, val in enumerate(params)}
            # Adjust query to use :1, :2, etc. placeholders
            query = query.replace('%s', ':%d').replace(':%d', ':{}')
            query = query.format(*[i + 1 for i in range(len(params))])
        else:
            param_dict = {'1': params}  # Single value case
            query = query.replace('%s', ':1')

        # Debug logging
        logging.debug(f"Executing query: {query}")
        logging.debug(f"With parameters: {param_dict}")

        # Execute query
        if param_dict:
            result = db.session.execute(text(query), param_dict)
        else:
            result = db.session.execute(text(query))

        # Handle results
        if fetch:
            columns = [col.name for col in result.cursor.description]
            rows = result.fetchall()
            return [dict(zip(columns, row)) for row in rows] if rows else []

        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        logging.error(f"Database error in query '{query}' with params {param_dict}: {str(e)}")
        raise  # Raise exception for debugging on Render
        return False
    

def get_db_connection():
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    return conn

def send_approval_email(user_email):
    try:
        msg = Message(
            subject="Your Account Has Been Approved",
            sender=app.config['MAIL_USERNAME'],
            recipients=[user_email],
            body=f"""Dear User,
            
Your account has been approved by the chairman. You can now log in to the system.

Best regards,
Your Organization"""
        )
        mail.send(msg)
        app.logger.info(f"Approval email sent to {user_email}")
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")
        return False

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/student_register', methods=['POST', 'GET'])
def student_register():
    if request.method == 'POST':
        roll_number = request.form.get('roll_number')
        name = request.form.get('name')
        email = request.form.get('email')
        mobile_number = request.form.get('mobile_number')
        session_value = request.form.get('Session')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        department = request.form.get('department')
        semester = request.form.get('semester')

        # Validation checks
        if not re.match(r'^01[3-9]\d{8}$', mobile_number):
            flash("Invalid mobile number! It must be 11 digits and start with a valid operator code in Bangladesh.", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department, semester=semester)

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department, semester=semester)

        if not semester:
            flash("Semester is required!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department, semester=semester)

        # Check if email exists
        query = "SELECT * FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)
        if result:
            flash("Email is already registered!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department, semester=semester)

        # Check if roll number exists
        query = "SELECT * FROM student WHERE roll_number = %s"
        result = execute_query(query, (roll_number,), fetch=True)
        if result:
            flash("Roll Number is already registered!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department, semester=semester)

        hashed_password = sha256_crypt.encrypt(password)

        # Insert into userss table with is_approved = FALSE
        query = """
            INSERT INTO userss (roll_number, name, email, mobile_number, user_type, session, password, department, semester, is_approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        result = execute_query(query, (roll_number, name, email, mobile_number, 'student', session_value, hashed_password, department, semester, False), fetch=True)
        
        if not result:
            flash("Registration failed. Please try again.", "error")
            return redirect(url_for('student_register'))

        # Insert into student table
        query = """
            INSERT INTO student (roll_number, name, email, mobile_number, user_type, session, password, department, semester)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        execute_query(query, (roll_number, name, email, mobile_number, 'student', session_value, hashed_password, department, semester))

        flash("Registration successful! Your account is pending approval.", "success")
        return redirect(url_for('login'))

    return render_template('student_register.html')

@app.route('/teacher_register', methods=['POST', 'GET'])
def teacher_register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        designation = request.form.get('designation')
        mobile_number = request.form.get('mobile_number')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        department = request.form.get('department')

        # Validation checks
        if not re.match(r'^01[3-9]\d{8}$', mobile_number):
            flash("Invalid mobile number! It must be 11 digits and start with a valid operator code in Bangladesh.", "error")
            return render_template('teacher_register.html', name=name, email=email, designation=designation,
                                   mobile_number=mobile_number, department=department)

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('teacher_register.html', name=name, email=email, designation=designation,
                                   mobile_number=mobile_number, department=department)

        # Check if email exists
        query = "SELECT * FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)
        if result:
            flash("Email is already registered!", "error")
            return render_template('teacher_register.html', name=name, email=email, designation=designation,
                                   mobile_number=mobile_number, department=department)

        hashed_password = sha256_crypt.encrypt(password)

        # Insert into userss table with is_approved = FALSE
        query = """
            INSERT INTO userss (name, email, mobile_number, user_type, password, department, designation, is_approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        result = execute_query(query, (name, email, mobile_number, 'teacher', hashed_password, department, designation, False), fetch=True)
        
        if not result:
            flash("Registration failed. Please try again.", "error")
            return redirect(url_for('teacher_register'))

        # Insert into teacher table
        query = """
            INSERT INTO teacher (name, email, mobile_number, user_type, password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        execute_query(query, (name, email, mobile_number, 'teacher', hashed_password, department, designation))

        flash("Registration successful! Your account is pending approval.", "success")
        return redirect(url_for('login'))

    return render_template('teacher_register.html')

@app.route('/chairman_register', methods=['POST', 'GET'])
def chairman_register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        mobile_number = request.form.get('mobile_number')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        department = request.form.get('department')

        if not re.match(r'^01[3-9]\d{8}$', mobile_number):
            flash("Invalid mobile number! It must be 11 digits and start with a valid operator code in Bangladesh.", "error")
            return render_template('chairman_register.html', name=name, email=email,
                                   mobile_number=mobile_number, department=department)

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('chairman_register.html', name=name, email=email,
                                   mobile_number=mobile_number, department=department)

        # Check if email exists
        query = "SELECT * FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)
        if result:
            flash("Email is already registered!", "error")
            return render_template('chairman_register.html', name=name, email=email,
                                   mobile_number=mobile_number, department=department)

        hashed_password = sha256_crypt.encrypt(password)

        # Insert into userss table with is_approved = TRUE
        query = """
            INSERT INTO userss (name, email, mobile_number, user_type, password, department, designation, is_approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        result = execute_query(query, (name, email, mobile_number, 'chairman', hashed_password, department, 'Chairman', True), fetch=True)
        
        if not result:
            flash("Registration failed. Please try again.", "error")
            return redirect(url_for('chairman_register'))

        # Insert into chairman table
        query = """
            INSERT INTO chairman (name, email, mobile_number, user_type, password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        execute_query(query, (name, email, mobile_number, 'chairman', hashed_password, department, 'Chairman'))

        flash("Registration successful!", "success")
        return redirect(url_for('login'))
    return render_template('chairman_register.html')

@app.route('/staff_register', methods=['POST', 'GET'])
def staff_register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        designation = request.form.get('designation')
        mobile_number = request.form.get('mobile_number')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        department = request.form.get('department')

        # Validation checks
        if not re.match(r'^01[3-9]\d{8}$', mobile_number):
            flash("Invalid mobile number! It must be 11 digits and start with a valid operator code in Bangladesh.", "error")
            return render_template('staff_register.html', name=name, email=email, designation=designation,
                                   mobile_number=mobile_number, department=department)

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('staff_register.html', name=name, email=email, designation=designation,
                                   mobile_number=mobile_number, department=department)

        # Check if email exists
        query = "SELECT * FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)
        if result:
            flash("Email is already registered!", "error")
            return render_template('staff_register.html', name=name, email=email, designation=designation,
                                   mobile_number=mobile_number, department=department)

        hashed_password = sha256_crypt.encrypt(password)

        # Insert into userss table with is_approved = FALSE
        query = """
            INSERT INTO userss (name, email, mobile_number, user_type, password, department, designation, is_approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        result = execute_query(query, (name, email, mobile_number, 'staff', hashed_password, department, designation, False), fetch=True)
        
        if not result:
            flash("Registration failed. Please try again.", "error")
            return redirect(url_for('staff_register'))

        # Insert into staff table
        query = """
            INSERT INTO staff (name, email, mobile_number, user_type, password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        execute_query(query, (name, email, mobile_number, 'staff', hashed_password, department, designation))

        flash("Registration successful! Your account is pending approval.", "success")
        return redirect(url_for('login'))

    return render_template('staff_register.html')

@app.route('/registration_successfull')
def registration_successful():
    return render_template('registration_successful.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch the user from the database
        query = "SELECT * FROM userss WHERE email = %s"
        result = execute_query(query, (username,), fetch=True)

        if result:  # If the user exists
            user = result[0]

            # Verify the password
            if sha256_crypt.verify(password, user['password']):
                # Check if the user is approved
                if user['is_approved']:
                    # Log the user in
                    session['loggedin'] = True
                    session['email'] = user['email']
                    session['user_type'] = user['user_type']
                    flash("Login successful!", "success")
                    return redirect(url_for(f"{user['user_type']}_profile"))
                else:
                    flash("Your account is pending approval. Please wait for the chairman to approve your account.", "warning")
            else:
                flash('Invalid password!', 'error')
        else:
            flash('Invalid email!', 'error')

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        query = "SELECT * FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)
        if result:  
            token = s.dumps(email, salt='password-reset-salt')
            link = url_for('reset_password', token=token, _external=True)
            msg = Message(
                'Password Reset Request',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"Please click the following link to reset your password: {link}"
            mail.send(msg)
            
            flash("A password reset link has been sent to your email.", "info")
        else:
            flash("This email is not associated with any account.", "danger")
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash("The password reset link is invalid or has expired.", "warning")
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return redirect(url_for('reset_password', token=token))

        hashed_password = sha256_crypt.encrypt(new_password)

        # Update password in userss table
        query = "UPDATE userss SET password = %s WHERE email = %s"
        execute_query(query, (hashed_password, email))

        # Update password in the specific user type table
        query = "SELECT user_type FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)
        if result:
            user_type = result[0]['user_type']
            query = f"UPDATE {user_type} SET password = %s WHERE email = %s"
            execute_query(query, (hashed_password, email))

        flash("Your password has been reset successfully. You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/student_profile', methods=['GET', 'POST'])
def student_profile():
    if 'loggedin' in session and session['user_type'] == 'student':
        email = session['email']
        profile = execute_query("SELECT * FROM userss WHERE email = %s", (email,), fetch=True)[0]

        if request.method == 'POST':
            if 'password' in request.form and 'confirm_password' in request.form:
                password = request.form['password']
                confirm_password = request.form['confirm_password']
                if password == confirm_password:
                    hashed_password = sha256_crypt.encrypt(password)
                    execute_query("UPDATE userss SET password = %s WHERE email = %s", (hashed_password, email))
                    execute_query("UPDATE student SET password = %s WHERE email = %s", (hashed_password, email))
                    flash("Password updated successfully!", "success")
                else:
                    flash("Passwords do not match.", "error")
                return redirect(url_for('student_profile'))

            name = request.form['name']
            reg_no = request.form['reg_no']
            roll_number = request.form['roll_number']
            department = request.form['department']
            father_name = request.form['father_name']
            mother_name = request.form['mother_name']
            present_address = request.form['present_address']
            permanent_address = request.form['permanent_address']
            dob = request.form['dob']
            mobile_number = request.form['mobile_number']
            
            query = """
                UPDATE userss
                SET reg_no=%s, name=%s, roll_number=%s, department=%s, father_name=%s, mother_name=%s,
                    present_address=%s, permanent_address=%s, dob=%s, mobile_number=%s
                WHERE email=%s
            """
            execute_query(query, (reg_no, name, roll_number, department, father_name, mother_name, 
                               present_address, permanent_address, dob, mobile_number, email))
            
            query = """
                UPDATE student
                SET reg_no=%s, name=%s, roll_number=%s, department=%s, father_name=%s, mother_name=%s,
                    present_address=%s, permanent_address=%s, dob=%s, mobile_number=%s
                WHERE email=%s
            """
            execute_query(query, (reg_no, name, roll_number, department, father_name, mother_name, 
                               present_address, permanent_address, dob, mobile_number, email))
            
            flash("Profile updated successfully!", "success")
            return redirect(url_for('student_profile'))

        return render_template('student_profile.html', profile=profile)

    flash("Unauthorized access.", "error")
    return redirect(url_for('login'))

@app.route('/teacher_profile', methods=['GET', 'POST'])
def teacher_profile():
    if 'loggedin' in session and session['user_type'] == 'teacher':
        email = session['email']
        profile = execute_query("SELECT * FROM userss WHERE email = %s", (email,), fetch=True)[0]

        if request.method == 'POST':
            if 'password' in request.form and 'confirm_password' in request.form:
                password = request.form['password']
                confirm_password = request.form['confirm_password']
                if password == confirm_password:
                    hashed_password = sha256_crypt.encrypt(password)
                    execute_query("UPDATE userss SET password = %s WHERE email = %s", (hashed_password, email))
                    flash("Password updated successfully!", "success")
                else:
                    flash("Passwords do not match.", "error")
                return redirect(url_for('teacher_profile'))
            
            name = request.form['name']
            designation = request.form['designation']
            department = request.form['department']
            present_address = request.form['present_address']
            permanent_address = request.form['permanent_address']
            dob = request.form['dob']
            mobile_number = request.form['mobile_number']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            if password != confirm_password:
                flash("Passwords do not match", "error")
                return redirect(url_for('teacher_profile'))
                
            hashed_password = sha256_crypt.encrypt(password)
            
            query = """
                UPDATE userss
                SET name=%s, designation=%s, department=%s, password=%s, present_address=%s, 
                    permanent_address=%s, dob=%s, mobile_number=%s
                WHERE email=%s
            """
            execute_query(query, (name, designation, department, hashed_password, present_address, 
                               permanent_address, dob, mobile_number, email))
            
            query = """
                UPDATE teacher
                SET name=%s, designation=%s, department=%s, password=%s, present_address=%s, 
                    permanent_address=%s, dob=%s, mobile_number=%s
                WHERE email=%s
            """
            execute_query(query, (name, designation, department, hashed_password, present_address, 
                               permanent_address, dob, mobile_number, email))
            
            flash("Profile updated successfully!", "success")
            return redirect(url_for('teacher_profile'))

        return render_template('teacher_profile.html', profile=profile)

    flash("Unauthorized access.", "error")
    return redirect(url_for('login'))

@app.route('/chairman_profile', methods=['GET', 'POST'])
def chairman_profile():
    if 'loggedin' in session and session['user_type'] == 'chairman':
        email = session['email']
        profile = execute_query("SELECT * FROM userss WHERE email = %s", (email,), fetch=True)[0]

        if request.method == 'POST':
            if 'password' in request.form and 'confirm_password' in request.form:
                password = request.form['password']
                confirm_password = request.form['confirm_password']
                if password == confirm_password:
                    hashed_password = sha256_crypt.encrypt(password)
                    execute_query("UPDATE userss SET password = %s WHERE email = %s", (hashed_password, email))
                    flash("Password updated successfully!", "success")
                else:
                    flash("Passwords do not match.", "error")
                return redirect(url_for('chairman_profile'))
            
            name = request.form['name']
            designation = request.form['designation']
            department = request.form['department']
            present_address = request.form['present_address']
            permanent_address = request.form['permanent_address']
            dob = request.form['dob']
            mobile_number = request.form['mobile_number']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            if password != confirm_password:
                flash("Passwords do not match", "error")
                return redirect(url_for('chairman_profile'))
                
            hashed_password = sha256_crypt.encrypt(password)
            
            query = """
                UPDATE userss
                SET name=%s, designation=%s, department=%s, password=%s, present_address=%s, 
                    permanent_address=%s, dob=%s, mobile_number=%s
                WHERE email=%s
            """
            execute_query(query, (name, designation, department, hashed_password, present_address, 
                               permanent_address, dob, mobile_number, email))
            
            query = """
                UPDATE chairman
                SET name=%s, designation=%s, department=%s, password=%s, present_address=%s, 
                    permanent_address=%s, dob=%s, mobile_number=%s
                WHERE email=%s
            """
            execute_query(query, (name, designation, department, hashed_password, present_address, 
                               permanent_address, dob, mobile_number, email))
            
            flash("Profile updated successfully!", "success")
            return redirect(url_for('chairman_profile'))

        return render_template('chairman_profile.html', profile=profile)

    flash("Unauthorized access.", "error")
    return redirect(url_for('login'))

@app.route('/staff_profile', methods=['GET', 'POST'])
def staff_profile():
    if 'loggedin' in session and session['user_type'] == 'staff':
        email = session['email']
        profile = execute_query("SELECT * FROM userss WHERE email = %s", (email,), fetch=True)[0]
        return render_template('staff_profile.html', profile=profile)

    flash("Unauthorized access.", "error")
    return redirect(url_for('login'))

@app.route('/upload_photo', methods=['POST'])
def upload_photo():
    if 'loggedin' in session:
        email = session['email']
        user_type = session['user_type']

        if 'profile-photo' not in request.files:
            flash("No file part", "danger")
            return redirect(url_for(f'{user_type}_profile'))

        file = request.files['profile-photo']
        if file.filename == '':
            flash("No selected file", "danger")
            return redirect(url_for(f'{user_type}_profile'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace("\\", "/")
            file.save(file_path)
            
            query = "UPDATE userss SET photo=%s WHERE email=%s"
            execute_query(query, (filename, email))
            
            if user_type == 'student':
                query = "UPDATE student SET photo=%s WHERE email=%s"
                execute_query(query, (filename, email))
            
            flash("Profile photo updated successfully!", "success")
            return redirect(url_for(f'{user_type}_profile'))
        else:
            flash("Invalid file type!", "danger")
            return redirect(url_for(f'{user_type}_profile'))
    
    flash("Unauthorized access! Please log in first.", "danger")
    return redirect(url_for('login'))

@app.route('/view_results')
def view_results():
    if 'loggedin' not in session:
        return redirect(url_for('login'))  
    user_type = session.get('user_type')
    return render_template('view_results.html', user_type=user_type)

@app.route('/view_attendance', methods=['GET', 'POST'])
def view_attendance():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    user_type = session.get('user_type')
    attendance_data = None

    if request.method == 'POST':
        selected_session = request.form.get('session', '').strip()
        semester = request.form.get('semester', '').strip()
        course_code = request.form.get('course_code', '').strip()

        if not selected_session or not semester or not course_code:
            flash("All fields are required.", "error")
            return redirect(url_for('view_attendance'))

        try:
            query = """
                WITH class_counts AS (
                    SELECT 
                        course_code,
                        COUNT(*) AS total_classes
                    FROM 
                        classes
                    WHERE 
                        session = %s 
                        AND semester = %s
                        AND course_code = %s
                    GROUP BY 
                        course_code
                ),
                student_attendance AS (
                    SELECT 
                        sca.roll_number,
                        c.course_code,
                        c.class_date,
                        c.start_time,
                        c.end_time,
                        u.timein,
                        u.timeout,
                        -- Calculate total time the student was present
                        SUM(
                            CASE 
                                WHEN u.timein IS NOT NULL AND u.timeout IS NOT NULL THEN
                                    EXTRACT(EPOCH FROM (
                                        LEAST(c.end_time, GREATEST(c.start_time, u.timeout)) - 
                                        GREATEST(c.start_time, LEAST(c.end_time, u.timein))
                                    ) / 60
                                ELSE 0
                            END
                        ) AS total_minutes_present,
                        -- Calculate total duration of the class
                        EXTRACT(EPOCH FROM (c.end_time - c.start_time)) / 60 AS total_class_duration
                    FROM 
                        student_course_assign sca
                    JOIN 
                        classes c ON sca.course_code = c.course_code 
                    LEFT JOIN 
                        users_logs u ON sca.roll_number::text = u.serialnumber::text AND DATE(u.checkindate) = c.class_date
                    WHERE 
                        sca.session = %s 
                        AND sca.semester = %s
                        AND sca.course_code = %s
                    GROUP BY 
                        sca.roll_number, c.course_code, c.class_date, c.start_time, c.end_time, u.timein, u.timeout
                ),
                attended_classes AS (
                    SELECT 
                        roll_number,
                        course_code,
                        COUNT(CASE 
                            WHEN total_minutes_present >= (total_class_duration * 0.5) THEN 1
                        END) AS attended_classes
                    FROM 
                        student_attendance
                    GROUP BY 
                        roll_number, course_code
                )
                SELECT 
                    ac.roll_number,
                    ac.course_code,
                    COALESCE(cc.total_classes, 0) AS total_classes,
                    COALESCE(ac.attended_classes, 0) AS attended_classes,
                    CASE 
                        WHEN cc.total_classes > 0 THEN ROUND((ac.attended_classes * 100.0 / cc.total_classes), 2)
                        ELSE 0 
                    END AS attendance_percentage
                FROM 
                    attended_classes ac
                JOIN 
                    class_counts cc ON ac.course_code = cc.course_code
                WHERE
                    ac.course_code = %s
                ORDER BY 
                    ac.roll_number;
            """

            attendance_data = execute_query(query, (
                selected_session, semester, course_code,
                selected_session, semester, course_code,
                course_code
            ), fetch=True)

            if not attendance_data:
                flash("No attendance records available for the selected criteria.", "info")

        except Exception as e:
            print(f"Database Error: {str(e)}")
            flash(f"An error occurred while fetching attendance data: {str(e)}", "error")

    return render_template('view_attendance.html', 
                         attendance_data=attendance_data, 
                         user_type=user_type,
                         session=session)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'loggedin' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('login'))  

    email = session.get('email') 
    user_type = session.get('user_type')  

    if request.method == 'GET':
        return render_template('change_password.html', user_type=user_type)

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        query = "SELECT password FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)
        if not result:
            flash("User not found.", "error")
            return redirect(url_for('change_password'))
            
        current_password_hash = result[0]['password']

        if not sha256_crypt.verify(old_password, current_password_hash):
            flash("Old password is incorrect.", "error")
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash("New password and confirm password do not match.", "error")
            return redirect(url_for('change_password'))

        new_password_hash = sha256_crypt.encrypt(new_password)

        query = "UPDATE userss SET password = %s WHERE email = %s"
        execute_query(query, (new_password_hash, email))

        if user_type == 'student':
            query = "UPDATE student SET password = %s WHERE email = %s"
            execute_query(query, (new_password_hash, email))

        flash("Password updated successfully.", "success")
        return redirect(url_for('change_password'))

@app.route('/add_results', methods=['GET', 'POST'])
def add_results():
    if 'loggedin' not in session or session.get('user_type') != 'teacher':
        return redirect(url_for('login'))
    
    return render_template('add_results.html')

@app.route('/logout')
def logout():
    session.clear()  
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'loggedin' not in session:
        flash("Please log in to access your profile.", "error")
        return redirect(url_for('login'))

    email = session['email']
    user_type = session['user_type']

    try:
        profile = execute_query("SELECT * FROM userss WHERE email = %s", (email,), fetch=True)[0]
    except IndexError:
        flash("Profile not found.", "error")
        return redirect(url_for('logout'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')

        if not sha256_crypt.verify(current_password, profile['password']):
            flash("Incorrect current password. Please try again.", "error")
            return redirect(url_for('edit_profile'))

        name = request.form.get('name')
        mobile_number = request.form.get('mobile_number')
        present_address = request.form.get('present_address')
        permanent_address = request.form.get('permanent_address')

        try:
            query = """
                UPDATE userss
                SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s
                WHERE email=%s
            """
            execute_query(query, (name, mobile_number, present_address, permanent_address, email))

            if user_type == 'student':
                reg_no = request.form.get('reg_no')
                roll_number = request.form.get('roll_number')
                department = request.form.get('department')
                father_name = request.form.get('father_name')
                mother_name = request.form.get('mother_name')
                dob = request.form.get('dob')

                query = """
                    UPDATE student
                    SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s,
                        reg_no=%s, roll_number=%s, department=%s, father_name=%s, mother_name=%s, dob=%s
                    WHERE email=%s
                """
                execute_query(query, (name, mobile_number, present_address, permanent_address,
                                   reg_no, roll_number, department, father_name, mother_name, dob, email))

            elif user_type == 'teacher':
                designation = request.form.get('designation')
                department = request.form.get('department')
                dob = request.form.get('dob')

                query = """
                    UPDATE teacher
                    SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s,
                        designation=%s, department=%s, dob=%s
                    WHERE email=%s
                """
                execute_query(query, (name, mobile_number, present_address, permanent_address,
                             designation, department, dob, email))

            elif user_type == 'chairman':
                designation = request.form.get('designation')
                department = request.form.get('department')
                dob = request.form.get('dob')

                query = """
                    UPDATE chairman
                    SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s,
                        designation=%s, department=%s, dob=%s
                    WHERE email=%s
                """
                execute_query(query, (name, mobile_number, present_address, permanent_address,
                             designation, department, dob, email))

            elif user_type == 'staff':
                designation = request.form.get('designation')
                department = request.form.get('department')
                dob = request.form.get('dob')

                query = """
                    UPDATE staff
                    SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s,
                        designation=%s, department=%s, dob=%s
                    WHERE email=%s
                """
                execute_query(query, (name, mobile_number, present_address, permanent_address,
                             designation, department, dob, email))

            else:
                flash("Unknown user type.", "error")
                return redirect(url_for('edit_profile'))

            flash("Profile updated successfully!", "success")
            return redirect(url_for('edit_profile'))

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
            return redirect(url_for('edit_profile'))

    if user_type == 'student':
        return render_template('studentedit_profile.html', profile=profile, user_type=user_type)
    elif user_type == 'teacher':
        return render_template('teacheredit_profile.html', profile=profile, user_type=user_type)
    elif user_type == 'chairman':
        return render_template('chairmanedit_profile.html', profile=profile, user_type=user_type)
    elif user_type == 'staff':
        return render_template('staffedit_profile.html', profile=profile, user_type=user_type)
    else:
        flash("Unknown user type.", "error")
        return redirect(url_for('logout'))

@app.route('/submit_marks', methods=['POST'])
def submit_marks():
    try:
        if 'loggedin' not in session or session.get('user_type') != 'teacher':
            return jsonify({"error": "Unauthorized"}), 403

        teacher_email = session.get('email')
        data = request.json
        marks = data.get("marks", [])

        if not marks:
            return jsonify({"error": "No marks provided"}), 400

        course_code = marks[0].get('course_code')
        exam_type = marks[0].get('exam_type')

        if not course_code or not exam_type:
            return jsonify({"error": "Course code and exam type are required"}), 400

        # Verify teacher is assigned to this course
        query = """
            SELECT 1 FROM teacher_course_assign 
            WHERE email = %s AND course_code = %s
        """
        result = execute_query(query, (teacher_email, course_code), fetch=True)
        if not result:
            return jsonify({"error": "You are not assigned to this course"}), 403

        # Process marks
        for mark in marks:
            required_fields = ['roll_number', 'session', 'semester', 'course_code', 'exam_type', 'marks']
            if not all(field in mark for field in required_fields):
                return jsonify({"error": f"Invalid mark entry: {mark}"}), 400

            # Use PostgreSQL's ON CONFLICT syntax
            query = """
                INSERT INTO result (roll_number, session, semester, course_code, exam_type, marks)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (roll_number, session, semester, course_code, exam_type) 
                DO UPDATE SET marks = EXCLUDED.marks
            """
            params = (
                mark['roll_number'], mark['session'], mark['semester'],
                mark['course_code'], mark['exam_type'], mark['marks']
            )
            execute_query(query, params)

        return jsonify({"message": "Marks submitted successfully"}), 200

    except Exception as e:
        print(f"Error submitting marks: {e}")
        return jsonify({"error": f"Failed to submit marks: {str(e)}"}), 500

@app.route('/get_results', methods=['GET'])
def get_results():
    roll_number = request.args.get('roll_number')
    course_code = request.args.get('course_code')
    exam_type = request.args.get('exam_type')

    if not (roll_number and course_code and exam_type):
        return jsonify({"error": "Missing required parameters"}), 400

    query = """
    SELECT roll_number, course_code, exam_type, marks
    FROM result
    WHERE roll_number = %s AND course_code = %s AND exam_type = %s
    """

    try:
        results = execute_query(query, (roll_number, course_code, exam_type), fetch=True)

        if not results:
            return jsonify({"results": []})

        results_data = []
        for result in results:
            results_data.append({
                'roll_number': result['roll_number'],
                'course_code': result['course_code'],
                'exam_type': result['exam_type'],
                'marks': result['marks']
            })

        return jsonify({"results": results_data})

    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": "Failed to fetch results from the database"}), 500

@app.route('/get_students', methods=['GET'])
def get_students():
    session_value = request.args.get('session')
    semester = request.args.get('semester')
    course_code = request.args.get('course_code')

    if not (session_value and semester and course_code):
        return jsonify({"error": "Missing required parameters"}), 400

    query = """
    SELECT roll_number AS id 
    FROM student_course_assign
    WHERE session = %s AND semester = %s AND course_code = %s
    """

    try:
        students = execute_query(query, (session_value, semester, course_code), fetch=True)
        if not students:
            return jsonify({"students": []})  
        return jsonify({"students": students})  
    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": "Failed to fetch students from the database"}), 500

@app.route('/add_notice', methods=['POST', 'GET'])
def add_notice():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'teacher', 'staff']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        date = request.form.get('date')
        posted_by = session.get('email')
        file = request.files.get('file')

        if not title or not content or not date:
            flash("All fields except file are required!", "danger")
            return redirect(url_for('add_notice'))

        file_url = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_url = f"/{UPLOAD_FOLDER}/{filename}" 
        elif file:
            flash("Invalid file type. Only JPG, JPEG, and PNG are allowed.", "danger")
            return redirect(url_for('add_notice'))

        try:
            query = """
                INSERT INTO notices (title, content, posted_by, date, file_url)
                VALUES (%s, %s, %s, %s, %s)
            """
            params = (title, content, posted_by, date, file_url)
            execute_query(query, params)
            flash("Notice added successfully!", "success")
            return redirect(url_for('add_notice'))
        except Exception as err:
            print(f"Error adding notice: {err}")
            flash("An error occurred while adding the notice. Please try again.", "danger")
            return redirect(url_for('add_notice'))

    return render_template('add_notice.html')

@app.route('/notice_board', methods=['GET'])
def notice_board():
    try:
        query = """
            SELECT n.title, n.content, u.name as posted_by, n.date, n.file_url 
            FROM notices n
            LEFT JOIN userss u ON n.posted_by = u.email
            ORDER BY n.date DESC
        """
        notices = execute_query(query, fetch=True)
        error = None
    except Exception as e:
        print(f"Error fetching notices: {e}")
        notices = []
        error = "Failed to load notices. Please try again later."

    user_type = session.get('user_type', 'Guest')
    return render_template('notice_board.html', notices=notices, error=error, user_type=user_type)

@app.route('/student_course_assign', methods=['GET', 'POST'])
def student_course_assign():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'staff']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))
    return render_template('student_course_assign.html')

@app.route('/teacher_course_assign', methods=['GET', 'POST'])
def teacher_course_assign():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'staff']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))
    return render_template('teacher_course_assign.html')

@app.route('/submit_course_assignments', methods=['POST'])
def submit_course_assignments():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'staff']:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    students = data.get("students")

    if not students:
        return jsonify({"error": "No data provided"}), 400

    try:
        for student in students:
            # Use PostgreSQL's ON CONFLICT syntax
            query = """
                INSERT INTO student_course_assign (roll_number, session, semester, course_code, course_name, department)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (roll_number, session, semester, course_code) 
                DO UPDATE SET course_name = EXCLUDED.course_name, department = EXCLUDED.department
            """
            execute_query(query, (
                student["roll_number"], student["session"], student["semester"],
                student["course_code"], student["course_name"], student["department"]
            ))

        return jsonify({"success": True})
    except Exception as e:
        print(f"Error saving data: {e}")
        return jsonify({"error": "Failed to save data"}), 500

@app.route('/fetch_students', methods=['GET'])
def fetch_students():
    session_value = request.args.get('session')
    semester = request.args.get('semester')

    if not (session_value and semester):
        return jsonify({"error": "Missing required parameters"}), 400

    query = """
    SELECT roll_number, name, session, semester
    FROM student
    WHERE session = %s AND semester = %s
    """
    params = (session_value, semester)

    try:
        students = execute_query(query, params, fetch=True)
        if not students:
            return jsonify({"students": []}) 
        return jsonify({"students": students}) 
    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": "Failed to fetch students from the database"}), 500

@app.route('/submit_students', methods=['POST'])
def submit_students():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'staff']:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        data = request.json
        students = data.get('students', [])

        for student in students:
            # Use PostgreSQL's ON CONFLICT syntax
            query = """
                INSERT INTO student_course_assign (roll_number, session, semester, course_code, course_name, department)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (roll_number, session, semester, course_code) 
                DO UPDATE SET course_name = EXCLUDED.course_name, department = EXCLUDED.department
            """
            execute_query(query, (
                student['roll_number'],
                student['session'],
                student['semester'],
                student['course_code'],
                student['course_name'],
                student['department'],
            ))

        return jsonify({"message": "Students data successfully saved!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/add_course', methods=['GET', 'POST'])
def add_course():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'staff']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))
    return render_template('add_course.html') 

@app.route('/add_new_course', methods=['POST'])
def add_new_course():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'staff']:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        department = request.json.get('department')
        semester = request.json.get('semester')
        course_code = request.json.get('course_code')
        course_name = request.json.get('course_name')

        if not semester or not course_code or not course_name or not department:
            return {"error": "All fields are required!"}, 400

        # Use PostgreSQL's ON CONFLICT syntax
        query = """
            INSERT INTO course (semester, course_code, course_name, department)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (course_code) 
            DO UPDATE SET course_name = EXCLUDED.course_name, semester = EXCLUDED.semester, department = EXCLUDED.department
        """
        execute_query(query, (semester, course_code, course_name, department))

        return {"message": "Course added successfully!"}, 200
    except Exception as e:
        print(f"Error: {str(e)}") 
        return {"error": str(e)}, 500

@app.route('/get_courses', methods=['GET'])
def get_courses():
    semester = request.args.get('semester')
    department = request.args.get('department')
    if not semester or not department:
        return {"error": "Semester and department are required"}, 400

    query = """
    SELECT course_code, course_name 
    FROM course 
    WHERE semester = %s AND department = %s
    """

    try:
        courses = execute_query(query, (semester, department), fetch=True)
        return {"courses": courses}, 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return {"error": str(e)}, 500

@app.route('/get_teachers', methods=['GET'])
def get_teachers():
    department = request.args.get('department')

    if not department:
        return jsonify({"error": "Department is required"}), 400

    query = """
        SELECT name, id as teacher_id, email
        FROM teacher
        WHERE department = %s
    """

    try:
        teachers = execute_query(query, (department,), fetch=True)
        if not teachers:
            return jsonify({"teachers": []})
        return jsonify({"teachers": teachers}), 200
    except Exception as e:
        print(f"Error fetching teachers: {e}")
        return jsonify({"error": "Failed to fetch teachers"}), 500

@app.route('/assign_course_to_teacher', methods=['POST'])
def assign_course_to_teacher():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'staff']:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        data = request.json
        department = data.get('department')
        teacher_id = data.get('teacher_id')
        session_value = data.get('session')
        semester = data.get('semester')
        course_code = data.get('courseCode')
        course_name = data.get('courseName')

        if not all([department, teacher_id, session_value, semester, course_code, course_name]):
            return jsonify({"error": "All fields are required"}), 400

        # Get teacher info
        query = "SELECT name, email FROM teacher WHERE id = %s AND department = %s"
        teacher_result = execute_query(query, (teacher_id, department), fetch=True)

        if not teacher_result:
            return jsonify({"error": "Teacher not found in the specified department"}), 404

        teacher_name = teacher_result[0]['name']
        teacher_email = teacher_result[0]['email']

        # Use PostgreSQL's ON CONFLICT syntax
        query = """
            INSERT INTO teacher_course_assign (teacher_name, department, session, semester, course_code, course_name, email)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (teacher_name, session, semester, course_code) 
            DO UPDATE SET course_name = EXCLUDED.course_name, email = EXCLUDED.email
        """
        execute_query(query, (teacher_name, department, session_value, semester, course_code, course_name, teacher_email))

        return jsonify({"message": "Course successfully assigned to teacher!"}), 200
    except Exception as e:
        print(f"Error assigning course to teacher: {e}")
        return jsonify({"error": "Failed to assign course to teacher"}), 500

@app.route('/get_studentss', methods=['GET'])
def get_studentss():
    if 'loggedin' not in session or session.get('user_type') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        teacher_email = session.get('email')
        session_value = request.args.get('session')
        semester = request.args.get('semester')
        course_code = request.args.get('course_code')

        if not all([teacher_email, session_value, semester, course_code]):
            return jsonify({"error": "All parameters are required"}), 400

        # Verify teacher is assigned to this course
        query = """
            SELECT 1 FROM teacher_course_assign 
            WHERE email = %s AND course_code = %s AND semester = %s
        """
        result = execute_query(query, (teacher_email, course_code, semester), fetch=True)
        if not result:
            return jsonify({"error": "You are not assigned to this course"}), 403

        # Get students for this course
        query = """
            SELECT s.roll_number, s.name
            FROM student s
            JOIN student_course_assign sca ON s.roll_number = sca.roll_number
            WHERE sca.session = %s AND sca.semester = %s AND sca.course_code = %s
        """
        students = execute_query(query, (session_value, semester, course_code), fetch=True)

        return jsonify({"students": students}), 200
    except Exception as e:
        print(f"Error fetching students: {e}")
        return jsonify({"error": "Failed to fetch students"}), 500

@app.route('/get_coursess', methods=['GET'])
def get_coursess():
    if 'loggedin' not in session or session.get('user_type') != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403

    try:
        teacher_email = session.get('email')
        if not teacher_email:
            return jsonify({"error": "Teacher email is required"}), 400

        query = """
            SELECT course_code, course_name
            FROM teacher_course_assign
            WHERE email = %s
        """
        courses = execute_query(query, (teacher_email,), fetch=True)

        return jsonify({"courses": courses if courses else []}), 200
    except Exception as e:
        print(f"Error fetching courses: {e}")
        return jsonify({"error": "Failed to fetch courses"}), 500

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'loggedin' not in session or session.get('user_type') != 'student':
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    try:
        email = session.get('email')
        query = "SELECT roll_number FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)
        if not result:
            flash("Unable to fetch your roll number. Please contact the administrator.", "error")
            return redirect(url_for('feedback'))
        roll_number = result[0]['roll_number']
        
        course_code = request.form.get('course')
        rating = request.form.get('rating')
        comment = request.form.get('comment') or None

        if not roll_number or not course_code or not rating:
            flash("All fields except 'Additional Comments' are required!", "error")
            return redirect(url_for('feedback'))

        try:
            rating = int(rating)
            if not (1 <= rating <= 5):
                raise ValueError
        except ValueError:
            flash("Invalid rating value!", "error")
            return redirect(url_for('feedback'))

        # Check if student is enrolled in this course
        query = """
            SELECT 1 FROM student_course_assign 
            WHERE roll_number = %s AND course_code = %s
        """
        enrolled = execute_query(query, (roll_number, course_code), fetch=True)
        if not enrolled:
            flash("You are not enrolled in the selected course.", "error")
            return redirect(url_for('feedback'))

        # Check if feedback already submitted
        query = """
            SELECT 1 FROM course_feedback 
            WHERE roll_number = %s AND course_code = %s
        """
        feedback_exists = execute_query(query, (roll_number, course_code), fetch=True)
        if feedback_exists:
            flash("You have already submitted feedback for this course.", "error")
            return redirect(url_for('feedback'))

        # Insert feedback
        query = """
            INSERT INTO course_feedback (roll_number, course_code, rating, comment)
            VALUES (%s, %s, %s, %s)
        """
        execute_query(query, (roll_number, course_code, rating, comment))

        flash("Feedback submitted successfully!", "success")
        return redirect(url_for('feedback'))

    except Exception as e:
        print(f"Error submitting feedback: {e}")
        flash("Failed to submit feedback. Please try again.", "error")
        return redirect(url_for('feedback'))

@app.route('/feedback', methods=['GET'])
def feedback():
    if 'loggedin' not in session or session.get('user_type') != 'student':
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    email = session.get('email')
    query = """
        SELECT c.course_code, c.course_name
        FROM student_course_assign sca
        JOIN course c ON sca.course_code = c.course_code
        JOIN userss u ON u.roll_number = sca.roll_number
        WHERE u.email = %s
    """
    courses = execute_query(query, (email,), fetch=True)

    return render_template('feedback.html', courses=courses)

@app.route('/show_feedback', methods=['GET', 'POST'])
def show_feedback():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'teacher']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    try:
        courses_query = "SELECT course_code, course_name FROM course"
        courses = execute_query(courses_query, fetch=True)

        selected_course = None
        feedback_data = None
        chart_data = None
        average_rating = None

        if request.method == 'POST':
            selected_course = request.form.get('course')
            if not selected_course:
                flash("Please select a course.", "error")
                return redirect(url_for('show_feedback'))

            # Get feedback with student names
            query = """
                SELECT 
                    cf.id,
                    cf.roll_number,
                    s.name as student_name,
                    cf.course_code,
                    c.course_name,
                    cf.rating,
                    cf.comment,
                    cf.created_at
                FROM 
                    course_feedback cf
                JOIN 
                    student s ON cf.roll_number = s.roll_number
                JOIN 
                    course c ON cf.course_code = c.course_code
                WHERE 
                    cf.course_code = %s
                ORDER BY 
                    cf.created_at DESC
            """
            feedback_data = execute_query(query, (selected_course,), fetch=True)

            if feedback_data:
                # Calculate average rating
                total_ratings = sum(feedback['rating'] for feedback in feedback_data)
                average_rating = round(total_ratings / len(feedback_data), 2)

                # Prepare chart data
                rating_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
                for feedback in feedback_data:
                    rating = feedback['rating']
                    rating_counts[rating] += 1

                chart_data = {
                    "labels": ["1 Star", "2 Stars", "3 Stars", "4 Stars", "5 Stars"],
                    "counts": list(rating_counts.values())
                }

        return render_template(
            'show_feedback.html',
            courses=courses,
            feedbacks=feedback_data,
            chart_data=chart_data,
            selected_course=selected_course,
            average_rating=average_rating
        )
    except Exception as e:
        print(f"Error fetching feedback data: {e}")
        flash("Failed to fetch feedback data. Please try again.", "error")
        return redirect(url_for('chairman_profile'))

@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'loggedin' not in session or session.get('user_type') not in ['chairman', 'teacher']:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        session_value = request.form.get('session')
        semester = request.form.get('semester')
        course_code = request.form.get('course_code')
        class_date = request.form.get('class_date')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')

        if not all([session_value, semester, course_code, class_date, start_time, end_time]):
            flash("All fields are required.", "error")
            return redirect(url_for('add_class'))

        try:
            # Verify course exists
            query = "SELECT 1 FROM course WHERE course_code = %s"
            course_exists = execute_query(query, (course_code,), fetch=True)
            if not course_exists:
                flash("Invalid course code.", "error")
                return redirect(url_for('add_class'))

            # Insert class
            query = """
                INSERT INTO classes (session, semester, course_code, class_date, start_time, end_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            execute_query(query, (session_value, semester, course_code, class_date, start_time, end_time))
            flash("Class added successfully!", "success")
            return redirect(url_for('add_class'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
            return redirect(url_for('add_class'))

    return render_template('add_class.html')

@app.route('/chairman/approvals', methods=['GET', 'POST'])
def chairman_approvals():
    if 'loggedin' not in session or session.get('user_type') != 'chairman':
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')

        if not user_id or action not in ['approve', 'reject']:
            flash("Invalid request.", "error")
            return redirect(url_for('chairman_approvals'))

        if action == 'approve':
            # Get user email before approving
            query = "SELECT email FROM userss WHERE id = %s"
            user = execute_query(query, (user_id,), fetch=True)
            if not user:
                flash("User not found.", "error")
                return redirect(url_for('chairman_approvals'))

            user_email = user[0]['email']

            # Update approval status
            query = "UPDATE userss SET is_approved = TRUE WHERE id = %s"
            execute_query(query, (user_id,))

            # Send approval email
            send_approval_email(user_email)

            flash("User approved successfully! An email has been sent to the user.", "success")
        elif action == 'reject':
            # Delete user
            query = "DELETE FROM userss WHERE id = %s"
            execute_query(query, (user_id,))
            flash("User rejected successfully!", "success")

    # Get pending approvals
    query = """
        SELECT id, name, email, user_type, roll_number, department, session 
        FROM userss 
        WHERE is_approved = FALSE
        ORDER BY created_at DESC
    """
    pending_users = execute_query(query, fetch=True)

    return render_template('chairman_approvals.html', pending_users=pending_users)

@app.route('/manually_mark_attendance', methods=['GET', 'POST'])
def manually_mark_attendance():
    if 'loggedin' not in session or session.get('user_type') != 'teacher':
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    teacher_email = session.get('email')
    
    # Get teacher name
    query = "SELECT name FROM teacher WHERE email = %s"
    teacher_result = execute_query(query, (teacher_email,), fetch=True)
    if not teacher_result:
        flash("Teacher information not found.", "error")
        return redirect(url_for('login'))
    teacher_name = teacher_result[0]['name']

    if request.method == 'POST':
        class_id = request.form.get('class_id')
        roll_number = request.form.get('roll_number').strip()
        status = request.form.get('status')

        if not all([class_id, roll_number, status]):
            flash("All fields are required.", "error")
            return redirect(url_for('manually_mark_attendance'))

        # Get class details and verify teacher is assigned to this course
        query = """
            SELECT c.* FROM classes c
            JOIN teacher_course_assign tca ON 
                c.course_code = tca.course_code AND
                c.session = tca.session AND
                c.semester = tca.semester
            WHERE c.id = %s AND tca.email = %s
        """
        class_info = execute_query(query, (class_id, teacher_email), fetch=True)
        if not class_info:
            flash("Invalid class or unauthorized access.", "error")
            return redirect(url_for('manually_mark_attendance'))
        class_info = class_info[0]

        # Verify student is enrolled in this course
        query = """
            SELECT s.name 
            FROM student_course_assign sca
            JOIN student s ON sca.roll_number = s.roll_number
            WHERE sca.roll_number = %s 
              AND sca.course_code = %s 
              AND sca.session = %s 
              AND sca.semester = %s
        """
        student_info = execute_query(query, (
            roll_number, class_info['course_code'], 
            class_info['session'], class_info['semester']
        ), fetch=True)
        if not student_info:
            flash("Student not enrolled in this course.", "error")
            return redirect(url_for('manually_mark_attendance'))
        student_name = student_info[0]['name']

        # Calculate timein based on status
        timein = class_info['start_time']
        if status == 'Late':
            # Add 15 minutes to start time for late students
            timein = (datetime.datetime.combine(datetime.date.today(), timein) + 
                     datetime.timedelta(minutes=15)).time()

        # Insert attendance record
        query = """
            INSERT INTO users_logs 
            (username, serialnumber, device_uid, checkindate, timein, timeout, fingerout)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (serialnumber, checkindate) 
            DO UPDATE SET timein = EXCLUDED.timein, timeout = EXCLUDED.timeout, fingerout = EXCLUDED.fingerout
        """
        execute_query(query, (
            student_name,
            roll_number,
            f"Manual by {teacher_name}",
            class_info['class_date'],
            timein,
            class_info['end_time'],
            1  # fingerout
        ))

        flash(f"Attendance marked successfully for {student_name} ({roll_number}).", "success")
        return redirect(url_for('manually_mark_attendance'))

    # Get teacher's classes
    query = """
        SELECT c.id, c.course_code, c.class_date, 
               TO_CHAR(c.start_time, 'HH24:MI') as formatted_start_time,
               TO_CHAR(c.end_time, 'HH24:MI') as formatted_end_time,
               c.session, c.semester
        FROM classes c
        JOIN teacher_course_assign tca ON 
            c.course_code = tca.course_code AND
            c.session = tca.session AND
            c.semester = tca.semester
        WHERE tca.email = %s
          AND c.class_date BETWEEN CURRENT_DATE - INTERVAL '14 days' AND CURRENT_DATE + INTERVAL '14 days'
        ORDER BY c.class_date DESC, c.start_time DESC
    """
    classes = execute_query(query, (teacher_email,), fetch=True)

    return render_template('manually_mark_attendance.html', 
                         classes=classes or [],
                         teacher_name=teacher_name)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')