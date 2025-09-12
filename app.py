from flask import Flask, render_template, flash, redirect, url_for, request, session
from wtforms import Form, PasswordField, StringField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import mysql.connector

app = Flask(__name__)

# ---------------- DATABASE CONFIG ----------------
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "root",  # change if needed
    "database": "Gym"
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# ---------------- AUTH DECORATORS ----------------
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Please log in first!", "danger")
            return redirect(url_for('login'))
    return wrap

def is_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get('prof') == 1:
            return f(*args, **kwargs)
        else:
            flash("You are not authorized!", "danger")
            return redirect(url_for('login'))
    return wrap

# ---------------- WTForms ----------------
class ChangePasswordForm(Form):
    old_password = PasswordField('Existing Password')
    new_password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message="Passwords don't match")
    ])
    confirm = PasswordField('Confirm Password')

class EditProfileForm(Form):
    name = StringField('Name', [validators.DataRequired()])
    street = StringField('Street', [validators.DataRequired()])
    city = StringField('City', [validators.DataRequired()])
    phone = StringField('Phone', [validators.DataRequired(), validators.Length(min=10, max=15)])

# ---------------- ROUTES ----------------
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM info WHERE username = %s", (username,))
        data = cur.fetchone()

        if data:
            try:
                if sha256_crypt.verify(password_candidate, data['password']):
                    session['logged_in'] = True
                    session['username'] = username
                    session['prof'] = data['prof']
                    flash('You are logged in', 'success')

                    # Redirect based on role
                    if session['prof'] == 1:
                        return redirect(url_for('adminDash'))
                    elif session['prof'] == 3:
                        return redirect(url_for('trainorDash'))
                    elif session['prof'] == 2:
                        return redirect(url_for('recepDash'))
                    else:
                        return redirect(url_for('memberDash', username=username))
                else:
                    flash("Invalid password!", "danger")
            except ValueError:
                flash("Password format invalid in DB (must be sha256_crypt)", "danger")
        else:
            flash("Username not found!", "danger")

        cur.close()
        conn.close()

    return render_template('login.html')

# ---------------- CHANGE PASSWORD ----------------
@app.route('/update_password/<string:username>', methods=['GET', 'POST'])
@is_logged_in
def update_password(username):
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        new = form.new_password.data
        entered = form.old_password.data

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT password FROM info WHERE username = %s", (username,))
        old = cur.fetchone()['password']

        try:
            if sha256_crypt.verify(entered, old):
                cur.execute("UPDATE info SET password = %s WHERE username = %s",
                            (sha256_crypt.hash(new), username))
                conn.commit()
                flash('Password updated successfully!', 'success')
                return redirect(url_for('memberDash', username=session['username']))
            else:
                flash("Old password is incorrect!", "danger")
        except ValueError:
            flash("Stored password is not sha256_crypt hash!", "danger")

        cur.close()
        conn.close()

    return render_template('updatePassword.html', form=form)

# ---------------- DASHBOARDS ----------------
@app.route('/adminDash')
@is_logged_in
@is_admin
def adminDash():
    return render_template('adminDash.html')

@app.route('/memberDash/<string:username>')
@is_logged_in
def memberDash(username):
    return render_template('memberDash.html', username=username)

@app.route('/trainorDash')
@is_logged_in
def trainorDash():
    return render_template('trainorDash.html')

@app.route('/recepDash')
@is_logged_in
def recepDash():
    return render_template('recepDash.html')

# ---------------- PROFILE ----------------
@app.route('/profile/<string:username>')
@is_logged_in
def profile(username):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM info WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('profile.html', user=user)

# ---------------- EDIT PROFILE ----------------
@app.route('/edit_profile/<string:username>', methods=['GET', 'POST'])
@is_logged_in
def edit_profile(username):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM info WHERE username = %s", (username,))
    user = cur.fetchone()

    form = EditProfileForm(request.form)
    if request.method == 'GET':
        form.name.data = user['name']
        form.street.data = user['street']
        form.city.data = user['city']
        form.phone.data = user['phone']

    if request.method == 'POST' and form.validate():
        cur.execute("""
            UPDATE info 
            SET name=%s, street=%s, city=%s, phone=%s
            WHERE username=%s
        """, (form.name.data, form.street.data, form.city.data, form.phone.data, username))
        conn.commit()
        flash('Profile updated successfully!', 'success')
        cur.close()
        conn.close()
        return redirect(url_for('profile', username=username))

    cur.close()
    conn.close()
    return render_template('edit_profile.html', form=form)

# ---------------- LOGOUT ----------------
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.secret_key = "528491@JOKER"
    app.run(debug=True)
