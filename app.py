from flask import Flask, render_template, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from datetime import timedelta
import os

key = os.getenv('SECRET_KEY')
if not key:
    raise ValueError("Secret key not found. Set the SECRET_KEY environment variable.")
cipher_suite = Fernet(key)

# Initialize Flask app and database
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking modifications
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Can also be set to 'Strict' for stricter CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SECRET_KEY'] = key

db = SQLAlchemy(app)
# Initialize CSRF protection
csrf = CSRFProtect(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    passwords = db.relationship('Password', back_populates='user', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<User {self.username}>"

# Define the Password model
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='passwords')

    def __repr__(self):
        return f"<Password {self.website}>"
    
    # Method to encrypt password before storing in the database
    def set_password(self, plain_password):
        encrypted_password = cipher_suite.encrypt(plain_password.encode())  # Encrypt password
        self.password = encrypted_password.decode()  # Store encrypted password as string

    # Method to decrypt password when fetching from the database
    def get_password(self):
        decrypted_password = cipher_suite.decrypt(self.password.encode())  # Decrypt password
        return decrypted_password.decode()  # Return decrypted password

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class AddPasswordForm(FlaskForm):
    website = StringField('Website', validators=[DataRequired()])
    email = StringField('Email/Username', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save')

class SearchPasswordForm(FlaskForm):
    website = StringField('Website', validators=[DataRequired()])
    submit = SubmitField('Search')

class EmptyForm(FlaskForm):
    pass

# Create the database tables (only need to do this once)
with app.app_context():
    db.create_all()

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("CSRF token error. Please try again.", "error")
    return redirect(request.referrer)  # Redirect back to the previous page

# Home route to render the index.html template or redirect to login
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')  # Redirect to login if not logged in
    user = User.query.get(session['user_id'])  # Fetch the user from the database
    # Initialize the forms
    add_password_form = AddPasswordForm()
    search_password_form = SearchPasswordForm()
    empty_form = EmptyForm()  # Create an empty form for CSRF

    return render_template('index.html', username=user.username, add_password_form=add_password_form, search_password_form=search_password_form, form=empty_form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if the username already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash("Username already exists!", "error")
            return redirect('/signup')

        # Hash the password and save the user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect('/login')

    return render_template('signup.html', form=form)

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Ensure form is passed to the template
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if user exists
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash("Invalid username or password.", "error")
            return redirect('/login')

        # Store user ID in session
        session['user_id'] = user.id
        flash("Logged in successfully!", "success")
        return redirect('/')

    return render_template('login.html', form=form)  # Pass form to template

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully.", "success")

    return redirect('/login')

# Add Password Route
@app.route('/add', methods=['POST'])
def add():
    if 'user_id' not in session:
        flash("You must be logged in to add passwords.", "error")
        return redirect('/login')

    website = request.form['website']
    email = request.form['email']
    password = request.form['password']

    # Check if any field is empty
    if not website or not email or not password:
        flash("Please don't leave any fields empty!", "error")
        return redirect('/')

    # Create a new Password record associated with the current user
    new_password = Password(website=website, email=email, password=password, user_id=session['user_id'])
    new_password.set_password(password)  # Encrypt and set the password

    try:
        # Add the record to the database
        db.session.add(new_password)
        db.session.commit()
        flash("Password successfully saved!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error saving password to the database.", "error")

    return redirect('/')

# Search Password Route
@app.route('/search', methods=['POST'])
def search():
    if 'user_id' not in session:
        flash("You must be logged in to search for passwords.", "error")
        return redirect('/login')

    website = request.form['website']

    # Look for the website in the database, restricted to the logged-in user
    password_entry = Password.query.filter_by(website=website, user_id=session['user_id']).first()
    
    add_password_form = AddPasswordForm()  # Create the form for adding passwords
    search_password_form = SearchPasswordForm()  # Form for searching passwords
    empty_form = EmptyForm()

    if password_entry:
        # Decrypt the password before displaying it
        decrypted_password = password_entry.get_password()
        # Pass the search result back to the template
        return render_template('index.html', website=password_entry.website, email=password_entry.email, password=decrypted_password, add_password_form=add_password_form, search_password_form=search_password_form, form=empty_form)
    else:
        flash(f"No record of {website} found.", "error")
        return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)