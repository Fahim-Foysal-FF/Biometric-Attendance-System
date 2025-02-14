import csv
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
from datetime import datetime
import time
import re
import os 
from werkzeug.utils import secure_filename

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import secrets

from fast import execute_query

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'fafo1612@gmail.com'
app.config['MAIL_PASSWORD'] = 'njryxxemnjekosiy'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="app1"
)

UPLOAD_FOLDER = 'static/uploads'  
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

s = URLSafeTimedSerializer(app.secret_key)
def execute_query(query, params=(), fetch=False):
    cursor = mydb.cursor(dictionary=True)
    cursor.execute(query, params)
    if fetch:
        result = cursor.fetchall()
        cursor.close()
        return result
    mydb.commit()
    cursor.close()



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
        semester=request.form.get('semester')
        
        if not re.match(r'^01[3-9]\d{8}$', mobile_number):
            flash("Invalid mobile number! It must be 11 digits and start with a valid operator code in Bangladesh.", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department,semester=semester)

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department,semester=semester)

        mycursor = mydb.cursor()
        if not semester:
         flash("Semester is required!", "error")
         return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                           mobile_number=mobile_number, session_value=session_value, 
                           department=department, semester=semester)

      
        mycursor.execute("SELECT * FROM userss WHERE email = %s", (email,))
        if mycursor.fetchone():
            flash("Email is already registered!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department,semester=semester)

       
        mycursor.execute("SELECT * FROM student WHERE roll_number = %s", (roll_number,))
        if mycursor.fetchone():
            flash("Roll Number is already registered!", "error")
            return render_template('student_register.html', roll_number=roll_number, name=name, email=email, 
                                   mobile_number=mobile_number, session_value=session_value, department=department,semester=semester)

      
        hashed_password = sha256_crypt.encrypt(password)
        
        mycursor.execute("""
            INSERT INTO userss (roll_number, name, email, mobile_number, user_type, session, password, department,semester)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s,%s)
        """, (roll_number, name, email, mobile_number, 'student', session_value, hashed_password, department,semester))
        
        mycursor.execute("""
            INSERT INTO student (roll_number, name, email, mobile_number, user_type, session, password, department,semester)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s,%s)
        """, (roll_number, name, email, mobile_number, 'student', session_value, hashed_password, department,semester))
        
        mydb.commit()
        mycursor.close()

        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('student_register.html')

        
    
@app.route('/teacher_register', methods=['POST', 'GET'])
def teacher_register():
        
        
     if request.method == 'POST': 
        name = request.form.get('name')
        email = request.form.get('email')
        designation=request.form.get('designation')
        mobile_number = request.form.get('mobile_number')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        department = request.form.get('department')
       

        if not re.match(r'^01[3-9]\d{8}$', mobile_number):
            flash("Invalid mobile number! It must be 11 digits and start with a valid operator code in Bangladesh.", "error")
            return render_template('teacher_register.html', name=name, email=email,designation=designation,
                                   mobile_number=mobile_number, department=department)

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('teacher_register.html', name=name, email=email,designation=designation,
                                   mobile_number=mobile_number, department=department)

        mycursor = mydb.cursor()
       
        mycursor.execute("SELECT * FROM userss WHERE email = %s", (email,))
        if mycursor.fetchone():
            flash("Email is already registered!", "error")
            return render_template('teacher_register.html', name=name, email=email,designation=designation,
                                   mobile_number=mobile_number, department=department)


        hashed_password = sha256_crypt.encrypt(password)

       
         
        mycursor.execute("""
            INSERT INTO userss ( name, email, mobile_number, user_type ,password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ( name, email, mobile_number, 'teacher', hashed_password, department,designation))
        
        mycursor.execute("""
            INSERT INTO teacher ( name, email, mobile_number, user_type ,password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ( name, email, mobile_number, 'teacher', hashed_password, department,designation))
        
        mydb.commit()
        mycursor.close()

        flash("Registration successful!", "success")
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
            INSERT INTO userss ( name, email, mobile_number, user_type ,password, department,designation)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, ( name, email, mobile_number, 'chairman', hashed_password, department,'Chairman'))
        
        mycursor.execute("""
            INSERT INTO chairman ( name, email, mobile_number, user_type ,password, department,designation)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, ( name, email, mobile_number, 'chairman', hashed_password, department,'Chairman'))
        
        mydb.commit()
        mycursor.close()

        flash("Registration successful!", "success")
        return redirect(url_for('login'))
    return render_template('chairman_register.html')



@app.route('/staff_register',methods=['POST', 'GET'])
def staff_register():
    if request.method == 'POST': 
        name = request.form.get('name')
        email = request.form.get('email')
        designation=request.form.get('designation')
        mobile_number = request.form.get('mobile_number')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        department = request.form.get('department')
       

        if not re.match(r'^01[3-9]\d{8}$', mobile_number):
            flash("Invalid mobile number! It must be 11 digits and start with a valid operator code in Bangladesh.", "error")
            return render_template('teacher_register.html', name=name, email=email,designation=designation,
                                   mobile_number=mobile_number, department=department)

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('teacher_register.html', name=name, email=email,designation=designation,
                                   mobile_number=mobile_number, department=department)

        mycursor = mydb.cursor()
       
        mycursor.execute("SELECT * FROM userss WHERE email = %s", (email,))
        if mycursor.fetchone():
            flash("Email is already registered!", "error")
            return render_template('teacher_register.html', name=name, email=email,designation=designation,
                                   mobile_number=mobile_number, department=department)


        hashed_password = sha256_crypt.encrypt(password)

       
         
        mycursor.execute("""
            INSERT INTO userss ( name, email, mobile_number, user_type, password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ( name, email, mobile_number, 'staff', hashed_password, department,designation))
        
        mycursor.execute("""
            INSERT INTO staff ( name, email, mobile_number, user_type, password, department, designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ( name, email, mobile_number, 'staff', hashed_password, department,designation))
        
        mydb.commit()
        mycursor.close()

        flash("Registration successful!", "success")
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
        query = "SELECT * FROM userss WHERE email = %s"
        result = execute_query(query, (username,), fetch=True)
        if result:  
            user = result[0]  
            if sha256_crypt.verify(password, user['password']):            
                session['loggedin'] = True
                session['email'] = user['email']
                session['user_type'] = user['user_type']          
                return redirect(url_for(f"{user['user_type']}_profile"))
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
        # Decode the token to extract the email
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash("The password reset link is invalid or has expired.", "warning")
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return redirect(url_for('reset_password', token=token))  

        # Hash the new password
        hashed_password = sha256_crypt.encrypt(new_password)

        # Identify the user's type and update the corresponding table
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
            
            # Update the password in the specific user type table
            update_user_type_query = f"UPDATE {user_type} SET password = %s WHERE email = %s"
            execute_query(update_user_type_query, (hashed_password, email))
            
            # Update the password in the centralized users table
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

  
@app.route('/view_attendance')
def view_attendance():
    if 'loggedin' not in session:
        return redirect(url_for('login')) 
    user_type = session.get('user_type')

   
    return render_template('view_attendance.html', user_type=user_type)


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
        # Fetch the user's profile from the `users` table
        profile = execute_query("SELECT * FROM userss WHERE email = %s", (email,), fetch=True)[0]
    except IndexError:
        flash("Profile not found.", "error")
        return redirect(url_for('logout'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')

        # Verify the current password
        if not sha256_crypt.verify(current_password, profile['password']):
            flash("Incorrect current password. Please try again.", "error")
            return redirect(url_for('edit_profile'))

        # Fetch updated details from the form
        name = request.form.get('name')
        mobile_number = request.form.get('mobile_number')
        present_address = request.form.get('present_address')
        permanent_address = request.form.get('permanent_address')

        try:
            # Update the `users` table
            execute_query(
                """
                UPDATE userss
                SET name=%s, mobile_number=%s, present_address=%s, permanent_address=%s
                WHERE email=%s
                """,
                (name, mobile_number, present_address, permanent_address, email)
            )

            # Update the respective user type table
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

    # Render the appropriate edit profile template based on user type
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
        teacher_name = session.get('teacher_name')
        if not teacher_name:
            return jsonify({"error": "Unauthorized: Please log in"}), 403

        data = request.json
        print("Received data:", data)  # Log incoming data
        marks = data.get('marks', [])

        if not marks:
            return jsonify({"error": "Marks data is required"}), 400

        course_code = marks[0]['course_code']
        exam_type = marks[0]['exam_type']

        cursor = mydb.cursor(dictionary=True)

        # Verify if the teacher is assigned to this course
        verify_query = """
            SELECT 1 FROM teacher_course_assign WHERE teacher_name = %s AND course_code = %s
        """
        cursor.execute(verify_query, (teacher_name, course_code,))
        if not cursor.fetchone():
            return jsonify({"error": "You are not assigned to this course"}), 403

        # Insert or update marks in the `result` table
        for mark in marks:
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
        traceback.print_exc()  # Log the full traceback
        mydb.rollback()
        return jsonify({"error": "Failed to submit marks"}), 500

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
        # Debug: Print the query and parameters
        print(f"Executing query: {query}")
        print(f"Parameters: roll_number={roll_number}, course_code={course_code}, exam_type={exam_type}")

        results = execute_query(query, (roll_number, course_code, exam_type), fetch=True)

        # Debug: Print the results fetched from the database
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

        # Debug: Print the final data being returned
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
    
 

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}



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

    # Fetch user_type from session or set a default
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
        if not students:
            return jsonify({"students": []})  # No students found
        return jsonify({"students": students})  # Return matched students
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
                student['department'],
                student['course_code'],
                student['course_name'],
                
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
            return jsonify({"teachers": []})  # No teachers found

        return jsonify({"teachers": teachers}), 200
    except Exception as e:
        print(f"Error fetching teachers: {e}")
        return jsonify({"error": "Failed to fetch teachers"}), 500



@app.route('/assign_course_to_teacher', methods=['POST'])
def assign_course_to_teacher():
    try:
        # Extract data from the request JSON
        data = request.json
        department = data.get('department')
        teacher_id = data.get('teacher_id')  # Use teacher_id instead of teacher_name
        session = data.get('session')
        semester = data.get('semester')
        course_code = data.get('courseCode')
        course_name = data.get('courseName')

        # Validate all fields
        if not all([department, teacher_id, session, semester, course_code, course_name]):
            return jsonify({"error": "All fields are required"}), 400

        # Fetch the teacher's name and email from the `teacher` table based on their ID
        teacher_query = "SELECT name, email FROM teacher WHERE teacher_id = %s AND department = %s"
        teacher_params = (teacher_id, department)
        teacher_result = execute_query(teacher_query, teacher_params, fetch=True)

        if not teacher_result:
            return jsonify({"error": "Teacher not found in the specified department"}), 404

        teacher_name = teacher_result[0]['name']
        teacher_email = teacher_result[0]['email']

        # Construct the SQL query to insert/update the teacher's course assignment
        query = """
            INSERT INTO teacher_course_assign (teacher_name, department, session, semester, course_code, course_name, email)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            course_name = VALUES(course_name),
            email = VALUES(email)
        """
        params = (teacher_name, department, session, semester, course_code, course_name, teacher_email)

        # Execute the query
        execute_query(query, params, fetch=False)

        return jsonify({"message": "Course successfully assigned to teacher!"}), 200
    except Exception as e:
        print(f"Error assigning course to teacher: {e}")
        return jsonify({"error": "Failed to assign course to teacher"}), 500
    
@app.route('/get_studentss', methods=['GET'])
def get_studentss():
    try:
        # Extract teacher's name from the session (assuming it's stored during login)
        teacher_name = session.get('teacher_name')
        session_year = request.args.get('session')
        semester = request.args.get('semester')
        course_code = request.args.get('course_code')

        if not all([teacher_name, session_year, semester, course_code]):
            return jsonify({"error": "All parameters are required"}), 400

        cursor = mydb.cursor(dictionary=True)

        # Verify that the teacher is assigned to the course
        verify_query = """
            SELECT 1
            FROM teacher_course_assign
            WHERE teacher_name = %s AND course_code = %s AND semester = %s
        """
        cursor.execute(verify_query, (teacher_name, course_code, semester))
        if not cursor.fetchone():
            return jsonify({"error": "You are not assigned to this course"}), 403

        # Fetch students enrolled in the course
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
        # Get the logged-in teacher's email from the session
        teacher_email = session.get('email')  # Use 'email' from the session directly

        if not teacher_email:
            return jsonify({"error": "Teacher email is required"}), 400

        # Fetch all courses assigned to the teacher
        query = """
            SELECT course_code, course_name
            FROM teacher_course_assign
            WHERE email = %s
        """
        params = (teacher_email,)

        # Execute the query and fetch results
        courses = execute_query(query, params, fetch=True)

        # Return the courses or an empty list if no courses are assigned
        return jsonify({"courses": courses if courses else []}), 200
    except Exception as e:
        print(f"Error fetching courses: {e}")
        return jsonify({"error": "Failed to fetch courses"}), 500
    
    
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    try:
        # Get the logged-in user's email from the session
        email = session.get('email')

        if not email:
            flash("You are not logged in or your session has expired.", "error")
            return redirect(url_for('login'))

        # Fetch the student's roll number based on the email
        query = "SELECT roll_number FROM userss WHERE email = %s"
        result = execute_query(query, (email,), fetch=True)

        if not result:
            flash("Unable to fetch your roll number. Please contact the administrator.", "error")
            return redirect(url_for('feedback'))

        roll_number = result[0]['roll_number']  # Extract roll number from the query result

        # Get data from the form
        course_code = request.form.get('course')
        rating = request.form.get('rating')  # Required field
        comment = request.form.get('comment') or None  # Optional field

        # Validate required fields
        if not roll_number or not course_code or not rating:
            flash("All fields except 'Additional Comments' are required!", "error")
            return redirect(url_for('feedback'))

        # Ensure rating is valid
        try:
            rating = int(rating)
            if not (1 <= rating <= 5):
                raise ValueError
        except ValueError:
            flash("Invalid rating value!", "error")
            return redirect(url_for('feedback'))

        # Insert feedback into the database
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
    # Get the logged-in user's email from the session
    email = session.get('email')

    if not email:
        flash("You are not logged in or your session has expired.", "error")
        return redirect(url_for('login'))

    # Fetch courses based on the user's email
    query = """
        SELECT c.course_code, c.course_name
        FROM student_course_assign e
        INNER JOIN course c ON e.course_code = c.course_code
        INNER JOIN userss u ON u.roll_number = e.roll_number
        WHERE u.email = %s
    """
    courses = execute_query(query, (email,), fetch=True)

    # Render the feedback page with the fetched courses
    return render_template('feedback.html', courses=courses)



@app.route('/show_feedback', methods=['GET'])
def show_feedback():
    try:
        # Fetch feedback data from the database
        query = """
            SELECT cf.roll_number, cf.course_code, c.course_name, cf.rating, cf.comment
            FROM course_feedback cf
            INNER JOIN course c ON cf.course_code = c.course_code
        """
        feedbacks = execute_query(query, fetch=True)

        return render_template('show_feedback.html', feedbacks=feedbacks)
    except Exception as e:
        print(f"Error fetching feedback: {e}")
        flash("Failed to load feedback data. Please try again later.", "error")
        return render_template('show_feedback.html', feedbacks=[])


@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if request.method == 'POST':
        # Get form data
        session = request.form.get('session')
        semester = request.form.get('semester')
        course_code = request.form.get('course_code')
        class_date = request.form.get('class_date')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')

        # Validate the data
        if not session or not semester or not course_code or not class_date or not start_time or not end_time:
            flash("All fields are required.", "error")
            return redirect(url_for('add_class'))

        try:
            # Insert data into the database
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


if__name__='__main__'
app.run(debug=True)
