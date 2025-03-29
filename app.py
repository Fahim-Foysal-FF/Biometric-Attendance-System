import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from datetime import datetime, timedelta
import time
from flask_mail import Mail, Message
import re
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.hash import sha256_crypt
import secrets
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)



# Get PostgreSQL URL from environment (no fallback)
database_url = os.environ['DATABASE_URL']  # Will raise error if not set

# Fix URL format for SQLAlchemy
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
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
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize serializer
s = URLSafeTimedSerializer(app.secret_key)

# Database models would go here (example)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # Add other fields as needed

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def execute_query(query, params=(), fetch=False):
    try:
        result = db.session.execute(query, params)
        if fetch:
            return [dict(row) for row in result]
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logging.error(f"Database error: {e}")
        return False

# Your routes would go here (keep all your existing route functions)
@app.route('/')
def home():
    return render_template('index.html')

# ... (keep all your other routes exactly as they are)


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

        mycursor = mydb.cursor()
        mycursor.execute("SELECT * FROM userss WHERE email = %s", (email,))
        if mycursor.fetchone():
            flash("Email is already registered!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department, semester=semester)

        mycursor.execute("SELECT * FROM student WHERE roll_number = %s", (roll_number,))
        if mycursor.fetchone():
            flash("Roll Number is already registered!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department, semester=semester)

        hashed_password = sha256_crypt.encrypt(password)

        # Insert into userss table with is_approved = FALSE
        mycursor.execute("""
            INSERT INTO userss (roll_number, name, email, mobile_number, user_type, session, password, department, semester, is_approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (roll_number, name, email, mobile_number, 'student', session_value, hashed_password, department, semester, False))

        # Insert into student table
        mycursor.execute("""
            INSERT INTO student (roll_number, name, email, mobile_number, user_type, session, password, department, semester)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (roll_number, name, email, mobile_number, 'student', session_value, hashed_password, department, semester))

        mydb.commit()
        mycursor.close()

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

        mycursor = mydb.cursor()
        mycursor.execute("SELECT * FROM userss WHERE email = %s", (email,))
        if mycursor.fetchone():
            flash("Email is already registered!", "error")
            return render_template('teacher_register.html', name=name, email=email, designation=designation,
                                   mobile_number=mobile_number, department=department)

        hashed_password = sha256_crypt.encrypt(password)

        # Insert into userss table with is_approved = FALSE
        mycursor.execute("""
            INSERT INTO userss (name, email, mobile_number, user_type, password, department, designation, is_approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, email, mobile_number, 'teacher', hashed_password, department, designation, False))

        # Insert into teacher table
        mycursor.execute("""
            INSERT INTO teacher (name, email, mobile_number, user_type, password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (name, email, mobile_number, 'teacher', hashed_password, department, designation))

        mydb.commit()
        mycursor.close()

        flash("Registration successful! Your account is pending approval.", "success")
        return redirect(url_for('login'))

    return render_template('teacher_register.html')
@app.route('/chairman_register',methods=['POST', 'GET'])
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

        mycursor = mydb.cursor()
       
        mycursor.execute("SELECT * FROM userss WHERE email = %s", (email,))
        if mycursor.fetchone():
            flash("Email is already registered!", "error")
            return render_template('chairman_register.html', name=name, email=email,
                                   mobile_number=mobile_number, department=department)


        hashed_password = sha256_crypt.encrypt(password)
       
       
         
        mycursor.execute("""
            INSERT INTO userss ( name, email, mobile_number, user_type ,password, department,designation,is_approved)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, ( name, email, mobile_number, 'chairman', hashed_password, department,'Chairman', True))
        
        mycursor.execute("""
            INSERT INTO chairman ( name, email, mobile_number, user_type ,password, department,designation)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, ( name, email, mobile_number, 'chairman', hashed_password, department,'Chairman'))
        
        mydb.commit()
        mycursor.close()

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

        mycursor = mydb.cursor()
        mycursor.execute("SELECT * FROM userss WHERE email = %s", (email,))
        if mycursor.fetchone():
            flash("Email is already registered!", "error")
            return render_template('staff_register.html', name=name, email=email, designation=designation,
                                   mobile_number=mobile_number, department=department)

        hashed_password = sha256_crypt.encrypt(password)

        # Insert into userss table with is_approved = FALSE
        mycursor.execute("""
            INSERT INTO userss (name, email, mobile_number, user_type, password, department, designation, is_approved)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, email, mobile_number, 'staff', hashed_password, department, designation, False))

        # Insert into staff table
        mycursor.execute("""
            INSERT INTO staff (name, email, mobile_number, user_type, password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (name, email, mobile_number, 'staff', hashed_password, department, designation))

        mydb.commit()
        mycursor.close()

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

        
        user_type_query = """
            SELECT 'student' AS user_type FROM student WHERE email = %s
            UNION
            SELECT 'teacher' AS user_type FROM teacher WHERE email = %s
            UNION
            SELECT 'chairman' AS user_type FROM chairman WHERE email = %s
            UNION
            SELECT 'staff' AS user_type FROM staff WHERE email = %s
        """
        result = execute_query(user_type_query, (email, email, email, email))

        if result:
            user_type = result[0]['user_type']
            
           
            update_user_type_query = f"UPDATE {user_type} SET password = %s WHERE email = %s"
            execute_query(update_user_type_query, (hashed_password, email))
          
            update_users_table_query = "UPDATE userss SET password = %s WHERE email = %s"
            execute_query(update_users_table_query, (hashed_password, email))

            flash("Your password has been reset successfully. You can now log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("User not found. Please contact support.", "danger")
            return redirect(url_for('forgot_password'))

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
                    execute_query("UPDATE userss SET password = %s WHERE email = %s", (hashed_password , email))
                    execute_query("UPDATE student SET password = %s WHERE email = %s", (hashed_password , email))
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
            execute_query(
                """
                UPDATE userss
                SET reg_no=%s, name=%s, roll_number=%s, department=%s, father_name=%s, mother_name=%s,
                    present_address=%s, permanent_address=%s, dob=%s, mobile_number=%s
                WHERE email=%s
                """,
                (reg_no, name, roll_number, department, father_name, mother_name, present_address, permanent_address, dob, mobile_number, email)
            )
            
            execute_query(
                """
                UPDATE student
                SET reg_no=%s, name=%s, roll_number=%s, department=%s, father_name=%s, mother_name=%s,
                    present_address=%s, permanent_address=%s, dob=%s, mobile_number=%s
                WHERE email=%s
                """,
                (reg_no, name, roll_number, department, father_name, mother_name, present_address, permanent_address, dob, mobile_number, email)
            )
            
            
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
                    execute_query("UPDATE userss SET password = %s WHERE email = %s", (hashed_password , email))
                    flash("Password updated successfully!", "success")
                else:
                    flash("Passwords do not match.", "error")
                return redirect(url_for('teacher_profile'))
            name=request.form['name']
            designation=request.form['designation']
            department = request.form['department']
            present_address = request.form['present_address']
            permanent_address = request.form['permanent_address']
            dob = request.form['dob']
            mobile_number = request.form['mobile_number']
            password=request.form['password']
            confirm_password=request.form['confirm_password']
            if password != confirm_password:
               flash("do not match confrim password ")
               return redirect(url_for('teacher_profile'))
            hashed_password = sha256_crypt.encrypt(password)
            execute_query(
                """
                UPDATE userss
                SET name=%s,designation=%s,department=%s,password=%s,present_address=%s, permanent_address=%s, dob=%s, 
                    mobile_number=%s
                WHERE email=%s
                """,
                ( name,designation,department,hashed_password,present_address, permanent_address, dob, mobile_number, email)
            )
            flash("Profile updated successfully!", "success")
            return redirect(url_for('teacher_profile'))

        return render_template('teacher_profile.html', profile=profile)



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
                    execute_query("UPDATE userss SET password = %s WHERE email = %s", (hashed_password , email))
                    flash("Password updated successfully!", "success")
                else:
                    flash("Passwords do not match.", "error")
                return redirect(url_for('chairman_profile'))
            name=request.form['name']
            designation=request.form['designation']
            department = request.form['department']
            present_address = request.form['present_address']
            permanent_address = request.form['permanent_address']
            dob = request.form['dob']
            mobile_number = request.form['mobile_number']
            password=request.form['password']
            confirm_password=request.form['confirm_password']
            if password != confirm_password:
               flash("do not match confrim password ")
               return redirect(url_for('chairman_profile'))
            hashed_password = sha256_crypt.encrypt(password)
            execute_query(
                """
                UPDATE userss
                SET name=%s,designation=%s,department=%s,password=%s,present_address=%s, permanent_address=%s, dob=%s, 
                    mobile_number=%s
                WHERE email=%s
                """,
                ( name,designation,department,hashed_password,present_address, permanent_address, dob, mobile_number, email)
            )
            flash("Profile updated successfully!", "success")
            return redirect(url_for('chairman_profile'))

        return render_template('chairman_profile.html', profile=profile)



@app.route('/staff_profile', methods=['GET', 'POST'])
def staff_profile():
    if 'loggedin' in session and session['user_type'] == 'staff':
        email = session['email']

        profile = execute_query("SELECT * FROM userss WHERE email = %s", (email,), fetch=True)[0]

    return render_template('staff_profile.html', profile=profile)

   



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
            if user_type == 'student':
             execute_query("UPDATE userss SET photo=%s WHERE email=%s", (filename, email))
             flash("Profile photo updated successfully!", "success")
             return redirect(url_for(f'{user_type}_profile'))
        
            execute_query("UPDATE userss SET photo=%s WHERE email=%s", (filename, email))
            flash("Profile photo updated successfully!", "success")
            return redirect(url_for(f'{user_type}_profile'))
        else:
            flash("Invalid file type!", "danger")
            return redirect(url_for(f'{user_type}_profile'))
    flash("Unauthorized access! Please log in first.", "danger")
    return redirect(url_for('login'))
  
        
   


from flask import Flask, render_template, session, redirect, url_for, flash, request

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

        print(f"Form Data - Session: {selected_session}, Semester: {semester}, Course Code: {course_code}")

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
                                    TIMESTAMPDIFF(
                                        MINUTE, 
                                        GREATEST(c.start_time, LEAST(c.end_time, u.timein)), 
                                        LEAST(c.end_time, GREATEST(c.start_time, u.timeout))
                                    )
                                ELSE 0
                            END
                        ) AS total_minutes_present,
                        -- Calculate total duration of the class
                        TIMESTAMPDIFF(MINUTE, c.start_time, c.end_time) AS total_class_duration
                    FROM 
                        student_course_assign sca
                    JOIN 
                        classes c ON sca.course_code = c.course_code 
                    LEFT JOIN 
                        users_logs u ON sca.roll_number = u.serialnumber AND DATE(u.checkindate) = c.class_date
                    WHERE 
                        sca.session = %s 
                        AND sca.semester = %s
                        AND sca.course_code = %s
                    GROUP BY 
                        sca.roll_number, c.course_code, c.class_date
                ),
                attended_classes AS (
                    SELECT 
                        roll_number,
                        course_code,
                        COUNT(CASE 
                            WHEN total_minutes_present >= (total_class_duration * 0.5) THEN 1  -- Adjust threshold as needed
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
                    ac.course_code = %s;
            """

            print(f"Query: {query}")
            print(f"Params: {selected_session}, {semester}, {course_code}, {selected_session}, {semester}, {course_code}, {course_code}")

            attendance_data = execute_query(query, (
                selected_session, semester, course_code,
                selected_session, semester, course_code,
                course_code
            ), fetch=True)

            print(f"Attendance Data: {attendance_data}")

            if not attendance_data:
                flash("No attendance records available for the selected criteria.", "info")

        except Exception as e:
            print(f"Database Error: {str(e)}")
            flash(f"An error occurred while fetching attendance data: {str(e)}", "error")

    return render_template('view_attendance.html', attendance_data=attendance_data, user_type=user_type)



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

       
       
        user = execute_query("SELECT password FROM userss WHERE email = %s", (email,), fetch=True)[0]
        current_password_hash = user['password']

          
        if not sha256_crypt.verify(old_password, current_password_hash):
                flash("Old password is incorrect.", "error")
                return redirect(url_for('change_password'))

          
        if new_password != confirm_password:
                flash("New password and confirm password do not match.", "error")
                return redirect(url_for('change_password'))

      
        new_password_hash = sha256_crypt.encrypt(new_password)

           
        execute_query(
                "UPDATE userss SET password = %s WHERE email = %s", 
                (new_password_hash, email)
            )
        execute_query(
                "UPDATE student SET password = %s WHERE email = %s", 
                (new_password_hash, email)
            )

        flash("Password updated successfully.", "success")
        return redirect(url_for('change_password'))
       


@app.route('/add_results', methods=['GET', 'POST'])
def add_results():
    return render_template('add_results.html')

 
@app.route('/logout')
def logout():
    session.clear()  
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

from passlib.hash import sha256_crypt

from passlib.hash import sha256_crypt  
  
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'loggedin' not in session:
        flash("Please log in to access your profile.", "error")
        return redirect(url_for('login'))

    email = session.get('email')
    user_type = session.get('user_type')

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
           
            execute_query(
                """
                UPDATE userss
                SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s
                WHERE email=%s
                """,
                (name, mobile_number, present_address, permanent_address, email)
            )

            
            if user_type == 'student':
                reg_no = request.form.get('reg_no')
                roll_number = request.form.get('roll_number')
                department = request.form.get('department')
                father_name = request.form.get('father_name')
                mother_name = request.form.get('mother_name')
                dob = request.form.get('dob')

                execute_query(
                    """
                    UPDATE student
                    SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s,
                        reg_no=%s, roll_number=%s, department=%s, father_name=%s, mother_name=%s, dob=%s
                    WHERE email=%s
                    """,
                    (name, mobile_number, present_address, permanent_address,
                     reg_no, roll_number, department, father_name, mother_name, dob, email)
                )

            elif user_type == 'teacher':
                designation = request.form.get('designation')
                department = request.form.get('department')
                dob = request.form.get('dob')
                

                execute_query(
                    """
                    UPDATE teacher
                    SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s,
                        designation=%s, department=%s, dob=%s
                    WHERE email=%s
                    """,
                    (name, mobile_number, present_address, permanent_address,
                     designation, department, dob, email)
                )

            elif user_type == 'chairman':
                designation = request.form.get('designation')
                department = request.form.get('department')
                dob = request.form.get('dob')

                execute_query(
                    """
                    UPDATE chairman
                    SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s,
                        designation=%s, department=%s, dob=%s
                    WHERE email=%s
                    """,
                    (name, mobile_number, present_address, permanent_address,
                     designation, department, dob, email)
                )

            elif user_type == 'staff':
                designation = request.form.get('designation')
                department = request.form.get('department')
                dob = request.form.get('dob')

                execute_query(
                    """
                    UPDATE staff
                    SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s,
                        designation=%s, department=%s, dob=%s
                    WHERE email=%s
                    """,
                    (name, mobile_number, present_address, permanent_address,
                     designation, department, dob, email)
                )

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



from flask import jsonify, request, session
import traceback

@app.route('/submit_marks', methods=['POST'])
def submit_marks():
    try:
       
        print("Session data:", session)

        
        teacher_email = session.get('email')
        if not teacher_email:
            return jsonify({"error": "Unauthorized: Please log in"}), 403

        
        data = request.json
        print("Received data:", data)  
        
        if not data or 'marks' not in data:
            return jsonify({"error": "Marks data is required"}), 400

        marks = data.get('marks', [])
        if not marks:
            return jsonify({"error": "No marks provided"}), 400

        
        course_code = marks[0].get('course_code')
        exam_type = marks[0].get('exam_type')

        if not course_code or not exam_type:
            return jsonify({"error": "Course code and exam type are required"}), 400

        cursor = mydb.cursor(dictionary=True)

        
        verify_query = """
            SELECT 1 FROM teacher_course_assign WHERE email = %s AND course_code = %s
        """
        cursor.execute(verify_query, (teacher_email, course_code,))
        if not cursor.fetchone():
            return jsonify({"error": "You are not assigned to this course"}), 403

       
        for mark in marks:
            
            required_fields = ['roll_number', 'session', 'semester', 'course_code', 'exam_type', 'marks']
            if not all(field in mark for field in required_fields):
                return jsonify({"error": f"Invalid mark entry: {mark}"}), 400

            query = """
                INSERT INTO result (roll_number, session, semester, course_code, exam_type, marks)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE marks = %s
            """
            params = (
                mark['roll_number'], mark['session'], mark['semester'],
                mark['course_code'], mark['exam_type'], mark['marks'], mark['marks']
            )
            cursor.execute(query, params)

       
        mydb.commit()
        return jsonify({"message": "Marks submitted successfully"}), 200

    except Exception as e:
       
        print(f"Error submitting marks: {e}")
        traceback.print_exc()  
        mydb.rollback()
        return jsonify({"error": f"Failed to submit marks: {str(e)}"}), 500
    

import traceback

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
        
        print(f"Executing query: {query}")
        print(f"Parameters: roll_number={roll_number}, course_code={course_code}, exam_type={exam_type}")

        results = execute_query(query, (roll_number, course_code, exam_type), fetch=True)

        
        print(f"Results from database: {results}")

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

        
        print(f"Returning data: {results_data}")

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
    
 





def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/add_notice', methods=['POST', 'GET'])
def add_notice():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        date = request.form.get('date')
        posted_by = request.form.get('posted_by')
        file = request.files.get('file')

        if not title or not content or not date or not posted_by:
            flash("All fields are required!", "danger")
            return redirect(url_for('add_notice'))

        file_url = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_url = f"/{UPLOAD_FOLDER}/{filename}" 
        elif file:
            flash("Invalid file type. Only PDF, JPG, JPEG, and PNG are allowed.", "danger")
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
        cursor = mydb.cursor()
        query = "SELECT title, content, posted_by, date, file_url FROM notices ORDER BY date DESC"
        cursor.execute(query)
        notices = cursor.fetchall()
        cursor.close()
        error = None
    except Exception as e:
        print(f"Error fetching notices: {e}")
        notices = []
        error = "Failed to load notices. Please try again later."

   
    user_type = session.get('user_type', 'Guest')

    return render_template('notice_board.html', notices=notices, error=error, user_type=user_type)


@app.route('/student_course_assign', methods=['GET', 'POST'])
def student_course_assign():
    return render_template('student_course_assign.html')

@app.route('/teacher_course_assign', methods=['GET', 'POST'])
def teacher_course_assign():
    return render_template('teacher_course_assign.html')

@app.route('/submit_course_assignments', methods=['POST'])
def submit_course_assignments():
    data = request.json
    students = data.get("students")

    if not students:
        return jsonify({"error": "No data provided"}), 400

    try:
        for student in students:
            query = """
            INSERT INTO student_course_assign (roll_number, session, semester, course_code)
            VALUES (%s, %s, %s, %s)
            """
            execute_query(query, (
                student["roll_number"], student["session"], student["semester"],
                student["course_code"]
            ))

        return jsonify({"success": True})
    except Exception as e:
        print(f"Error saving data: {e}")
        return jsonify({"error": "Failed to save data"}), 500

@app.route('/fetch_students', methods=['GET'])
def fetch_students():
    session = request.args.get('session')
    semester = request.args.get('semester')

    if not (session and semester):
        return jsonify({"error": "Missing required parameters"}), 400

    query = """
    SELECT roll_number, name, session, semester
    FROM student
    WHERE session = %s AND semester = %s
    """
    params = (session, semester)

    try:
        students = execute_query(query, params, fetch=True)
        print(f"Query: {query % params}") 
        print(f"Students Fetched: {students}")  
        if not students:
            return jsonify({"students": []}) 
        return jsonify({"students": students}) 
    except Exception as e:
        print(f"Database Error: {e}")
        return jsonify({"error": "Failed to fetch students from the database"}), 500


@app.route('/submit_students', methods=['POST'])
def submit_students():
    try:
        
        data = request.json
        students = data.get('students', [])

        cursor = mydb.cursor()

        sql = """
            INSERT INTO student_course_assign (roll_number, session, semester, course_code, course_name, department)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            course_name = VALUES(course_name)
        """

        for student in students:
            cursor.execute(sql, (
                student['roll_number'],
                student['session'],
                student['semester'],
                
                student['course_code'],
                student['course_name'],
                student['department'],
                
            ))

        mydb.commit()

        return jsonify({"message": "Students data successfully saved!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
   
@app.route('/add_course', methods=['GET', 'POST'])
def add_course():
    return render_template('add_course.html') 



@app.route('/add_new_course', methods=['POST'])
def add_new_course():
    try:
        
        department = request.json.get('department')
        semester = request.json.get('semester')
        course_code = request.json.get('course_code')
        course_name = request.json.get('course_name')

        if not semester or not course_code or not course_name or not department :
            return {"error": "All fields are required!"}, 400

        cursor = mydb.cursor()
        sql = "INSERT INTO course (semester, course_code, course_name,department) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (semester, course_code, course_name, department))

        mydb.commit()

        return {"message": "Course added successfully!"}, 200

    except Exception as e:
        print(f"Error: {str(e)}") 
        return {"error": str(e)}, 500



@app.route('/get_courses', methods=['GET'])
def get_courses():
    try:
        semester = request.args.get('semester')
        department = request.args.get('department')
        if not semester or not department:
            return {"error": "Semester and department are required"}, 400

        cursor = mydb.cursor(dictionary=True)
        sql = "SELECT course_code, course_name FROM course WHERE semester = %s AND department = %s"
        cursor.execute(sql, (semester, department))
        courses = cursor.fetchall()

        return {"courses": courses}, 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return {"error": str(e)}, 500

    


@app.route('/get_teachers', methods=['GET'])
def get_teachers():
    try:
        department = request.args.get('department')

        if not department:
            return jsonify({"error": "Department is required"}), 400

        query = """
            SELECT name, teacher_id, email
            FROM teacher
            WHERE department = %s
        """
        params = (department,)
        teachers = execute_query(query, params, fetch=True)

        if not teachers:
            return jsonify({"teachers": []})

        return jsonify({"teachers": teachers}), 200
    except Exception as e:
        print(f"Error fetching teachers: {e}")
        return jsonify({"error": "Failed to fetch teachers"}), 500



@app.route('/assign_course_to_teacher', methods=['POST'])
def assign_course_to_teacher():
    try:
       
        data = request.json
        department = data.get('department')
        teacher_id = data.get('teacher_id')  
        session = data.get('session')
        semester = data.get('semester')
        course_code = data.get('courseCode')
        course_name = data.get('courseName')

       
        if not all([department, teacher_id, session, semester, course_code, course_name]):
            return jsonify({"error": "All fields are required"}), 400

        teacher_query = "SELECT name, email FROM teacher WHERE teacher_id = %s AND department = %s"
        teacher_params = (teacher_id, department)
        teacher_result = execute_query(teacher_query, teacher_params, fetch=True)

        if not teacher_result:
            return jsonify({"error": "Teacher not found in the specified department"}), 404

        teacher_name = teacher_result[0]['name']
        teacher_email = teacher_result[0]['email']

        query = """
            INSERT INTO teacher_course_assign (teacher_name, department, session, semester, course_code, course_name, email)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            course_name = VALUES(course_name),
            email = VALUES(email)
        """
        params = (teacher_name, department, session, semester, course_code, course_name, teacher_email)

        execute_query(query, params, fetch=False)

        return jsonify({"message": "Course successfully assigned to teacher!"}), 200
    except Exception as e:
        print(f"Error assigning course to teacher: {e}")
        return jsonify({"error": "Failed to assign course to teacher"}), 500
    
@app.route('/get_studentss', methods=['GET'])
def get_studentss():
    try:
        teacher_name = session.get('teacher_name')
        session_year = request.args.get('session')
        semester = request.args.get('semester')
        course_code = request.args.get('course_code')

        if not all([teacher_name, session_year, semester, course_code]):
            return jsonify({"error": "All parameters are required"}), 400

        cursor = mydb.cursor(dictionary=True)

        verify_query = """
            SELECT 1
            FROM teacher_course_assign
            WHERE teacher_name = %s AND course_code = %s AND semester = %s
        """
        cursor.execute(verify_query, (teacher_name, course_code, semester))
        if not cursor.fetchone():
            return jsonify({"error": "You are not assigned to this course"}), 403

        students_query = """
            SELECT s.roll_number, s.name
            FROM student s
            INNER JOIN enrollment e ON s.roll_number = e.roll_number
            WHERE e.session = %s AND e.semester = %s AND e.course_code = %s
        """
        cursor.execute(students_query, (session_year, semester, course_code))
        students = cursor.fetchall()

        return jsonify({"students": students}), 200

    except Exception as e:
        print(f"Error fetching students: {e}")
        return jsonify({"error": "Failed to fetch students"}), 500


@app.route('/get_coursess', methods=['GET'])
def get_coursess():
    try:
      
        teacher_email = session.get('email')  
        if not teacher_email:
            return jsonify({"error": "Teacher email is required"}), 400

        query = """
            SELECT course_code, course_name
            FROM teacher_course_assign
            WHERE email = %s
        """
        params = (teacher_email,)

        
        courses = execute_query(query, params, fetch=True)

        return jsonify({"courses": courses if courses else []}), 200
    except Exception as e:
        print(f"Error fetching courses: {e}")
        return jsonify({"error": "Failed to fetch courses"}), 500
    
    
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    try:
        email = session.get('email')
        if not email:
            flash("You are not logged in or your session has expired.", "error")
            return redirect(url_for('login'))

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

       
        enrolled_courses_query = """
            SELECT course_code 
            FROM student_course_assign 
            WHERE roll_number = %s
        """
        enrolled_courses = execute_query(enrolled_courses_query, (roll_number,), fetch=True)
        enrolled_course_codes = [course['course_code'] for course in enrolled_courses]

        if course_code not in enrolled_course_codes:
            flash("You are not enrolled in the selected course and cannot provide feedback for it.", "error")
            return redirect(url_for('feedback'))

        feedback_check_query = """
            SELECT COUNT(*) AS feedback_count
            FROM course_feedback
            WHERE roll_number = %s AND course_code = %s
        """
        feedback_check_result = execute_query(feedback_check_query, (roll_number, course_code), fetch=True)
        feedback_count = feedback_check_result[0]['feedback_count']

        if feedback_count > 0:
            flash("You have already submitted feedback for this course.", "error")
            return redirect(url_for('feedback'))

        feedback_query = """
            INSERT INTO course_feedback (roll_number, course_code, rating, comment)
            VALUES (%s, %s, %s, %s)
        """
        execute_query(feedback_query, (roll_number, course_code, rating, comment), fetch=False)

        flash("Feedback submitted successfully!", "success")
        return redirect(url_for('feedback'))

    except Exception as e:
        print(f"Error submitting feedback: {e}")
        flash("Failed to submit feedback. Please try again.", "error")
        return redirect(url_for('feedback'))

@app.route('/feedback', methods=['GET'])
def feedback():
    email = session.get('email')
    if not email:
        flash("You are not logged in or your session has expired.", "error")
        return redirect(url_for('login'))

    query = """
        SELECT c.course_code, c.course_name
        FROM student_course_assign e
        INNER JOIN course c ON e.course_code = c.course_code
        INNER JOIN userss u ON u.roll_number = e.roll_number
        WHERE u.email = %s
    """
    courses = execute_query(query, (email,), fetch=True)

    return render_template('feedback.html', courses=courses)



@app.route('/show_feedback', methods=['GET', 'POST'])
def show_feedback():
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

            feedback_query = """
                SELECT 
                    cf.course_code,
                    c.course_name,
                    cf.rating,
                    cf.comment
                FROM 
                    course_feedback cf
                INNER JOIN 
                    course c ON cf.course_code = c.course_code
                WHERE 
                    cf.course_code = %s
            """
            feedback_data = execute_query(feedback_query, (selected_course,), fetch=True)

            if feedback_data:
                # Calculate average rating
                total_ratings = sum(feedback['rating'] for feedback in feedback_data)
                average_rating = total_ratings / len(feedback_data)

                # Prepare chart data
                rating_counts = {}
                for feedback in feedback_data:
                    rating = feedback['rating']
                    rating_counts[rating] = rating_counts.get(rating, 0) + 1

                chart_data = {
                    "labels": [f"Rating {rating}" for rating in rating_counts.keys()],
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
    if request.method == 'POST':
        # Get form data
        session = request.form.get('session')
        semester = request.form.get('semester')
        course_code = request.form.get('course_code')
        class_date = request.form.get('class_date')
        start_time = request.form.get('start_time')  # Fixed variable name
        end_time = request.form.get('end_time')  # Fixed variable name

        # Validate the data
        if not session or not semester or not course_code or not class_date or not start_time or not end_time:
            flash("All fields are required.", "error")
            return redirect(url_for('add_class'))

        try:
            query = """
                INSERT INTO classes (session, semester, course_code, class_date, start_time, end_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            execute_query(query, (session, semester, course_code, class_date, start_time, end_time))
            flash("Class added successfully!", "success")
            return redirect(url_for('add_class'))
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
            return redirect(url_for('add_class'))

    # For GET requests, render the form
    return render_template('add_class.html')





def send_approval_email(user_email):
    try:
        msg = Message(
            subject="Your Account Has Been Approved",
            sender=os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@yourdomain.com'),
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

@app.route('/chairman/approvals', methods=['GET', 'POST'])
def chairman_approvals():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')  # 'approve' or 'reject'

        if action == 'approve':
            # Fetch the user's email before approving
            query = "SELECT email FROM userss WHERE id = %s"
            user = execute_query(query, (user_id,), fetch=True)
            if user:
                user_email = user[0]['email']

                # Update the user's is_approved status to TRUE
                query = "UPDATE userss SET is_approved = TRUE WHERE id = %s"
                execute_query(query, (user_id,))

                # Send approval email
                send_approval_email(user_email)

                flash("User approved successfully! An email has been sent to the user.", "success")
            else:
                flash("User not found!", "error")

        elif action == 'reject':
            # Delete the user or mark them as rejected
            query = "DELETE FROM userss WHERE id = %s"
            execute_query(query, (user_id,))
            flash("User rejected successfully!", "success")

    # Fetch all pending users
    query = "SELECT id, name, email, user_type, roll_number, department, session FROM userss WHERE is_approved = FALSE"
    pending_users = execute_query(query, fetch=True)

    return render_template('chairman_approvals.html', pending_users=pending_users)




@app.route('/manually_mark_attendance', methods=['GET', 'POST'])
def manually_mark_attendance():
    # Check authentication
    if 'loggedin' not in session or session.get('user_type') != 'teacher':
        return redirect(url_for('login'))
    
    teacher_email = session.get('email')
    
    # Fetch teacher's name
    teacher_data = execute_query(
        "SELECT name FROM teacher WHERE email = %s", 
        (teacher_email,), 
        fetch=True
    )
    teacher_name = teacher_data[0]['name'] if teacher_data else teacher_email

    if request.method == 'POST':
        class_id = request.form.get('class_id')
        roll_number = request.form.get('roll_number').strip()
        status = request.form.get('status')
        
        # Get class details with teacher verification
        class_info = execute_query("""
            SELECT c.* FROM classes c
            JOIN teacher_course_assign tca ON 
                c.course_code = tca.course_code AND
                c.session = tca.session AND
                c.semester = tca.semester
            WHERE c.id = %s AND tca.email = %s
            LIMIT 1
        """, (class_id, teacher_email), fetch=True)
        
        if not class_info:
            flash("Invalid class or unauthorized access", "error")
            return redirect(url_for('manually_mark_attendance'))
        
        class_info = class_info[0]
        
        # Verify student enrollment and get username
        student_data = execute_query("""
            SELECT s.name 
            FROM student_course_assign sca
            JOIN student s ON sca.roll_number = s.roll_number
            WHERE sca.roll_number = %s 
              AND sca.course_code = %s 
              AND sca.session = %s 
              AND sca.semester = %s
            LIMIT 1
        """, (roll_number, class_info['course_code'], 
             class_info['session'], class_info['semester']), fetch=True)
        
        if not student_data:
            flash("Student not enrolled in this course", "error")
            return redirect(url_for('manually_mark_attendance'))
        
        student_username = student_data[0]['name']
        
        # Calculate timein
        timein = class_info['start_time']
        if status == 'Late':
            timein = (datetime.datetime.combine(datetime.date.today(), timein) + 
                     datetime.timedelta(minutes=15)).time()
        
        # Record attendance with student username
        success = execute_query("""
            INSERT INTO users_logs 
            (username, serialnumber, device_uid, checkindate, timein, timeout, fingerout)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            timein = VALUES(timein), 
            timeout = VALUES(timeout),
            fingerout = VALUES(fingerout)
        """, (
            student_username,  # Using actual student username instead of teacher note
            roll_number,
            f"Manual by {teacher_name}",
            class_info['class_date'],
            timein,
            class_info['end_time'],
            1  # fingerout
        ))
        
        if success:
            flash(f"Marked {status}: {roll_number} ({student_username}) for {class_info['course_code']} on {class_info['class_date']}", "success")
        else:
            flash("Failed to record attendance", "error")
    
    # Get teacher's classes
    classes = execute_query("""
        SELECT c.id, c.course_code, c.class_date, 
               DATE_FORMAT(c.start_time, '%H:%i') as formatted_start_time,
               DATE_FORMAT(c.end_time, '%H:%i') as formatted_end_time,
               c.session, c.semester
        FROM classes c
        JOIN teacher_course_assign tca ON 
            c.course_code = tca.course_code AND
            c.session = tca.session AND
            c.semester = tca.semester
        WHERE tca.email = %s
          AND c.class_date BETWEEN CURDATE() - INTERVAL 14 DAY AND CURDATE() + INTERVAL 14 DAY
        ORDER BY c.class_date DESC, c.start_time DESC
    """, (teacher_email,), fetch=True)
    
    return render_template('manually_mark_attendance.html', 
                         classes=classes or [],
                         teacher_name=teacher_name)

    

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')
