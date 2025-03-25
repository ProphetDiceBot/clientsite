from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from functools import wraps
import re  # Import the regular expression module

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb+srv://0p3nbullet:aiJ7QYL75t5pu0mo@prophetdice.8605b.mongodb.net/fiverr_clone_db'
app.secret_key = 'your_secret_key'  # Set a secret key for sessions
mongo = PyMongo(app)

# Decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_valid_email(email):
    """
    Validates the email format using a regular expression.
    """
    return re.match(r"^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$", email) is not None

@app.route('/')
def index():
    """
    This route renders the main HTML page.
    """
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    """
    Handles user registration (signup).
    """
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Validation
    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    if not is_valid_email(email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400

    # Check if the email is already taken
    if mongo.db.users.find_one({'email': email}):
        return jsonify({'success': False, 'message': 'Email already exists'}), 400

    hashed_password = generate_password_hash(password)
    user_data = {
        'name': name,
        'email': email,
        'password': hashed_password,
    }

    try:
        user_id = mongo.db.users.insert_one(user_data).inserted_id
        session['user_id'] = str(user_id)  # Set the user_id in the session
        return jsonify({'success': True, 'message': 'User created successfully'}), 201
    except Exception as e:
        print(f"Error creating user: {e}")
        return jsonify({'success': False, 'message': 'Failed to create user'}), 500

@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login.
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    user = mongo.db.users.find_one({'email': email})

    if user and check_password_hash(user['password'], password):
        session['user_id'] = str(user['_id'])  # Set the user_id in the session
        return jsonify({'success': True, 'message': 'Logged in successfully'}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/logout')
def logout():
    """
    Handles user logout.
    """
    session.pop('user_id', None)  # Clear the user session
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Placeholder route for the dashboard. Now requires login.
    """
    user_id = session.get('user_id')
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if user:
        return jsonify({'success': True, 'message': f"Welcome to the Dashboard, {user['name']}!"}), 200
    else:
        return jsonify({'success': False, 'message': "User not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)
