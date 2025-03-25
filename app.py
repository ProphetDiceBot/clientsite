from flask import Flask, request, jsonify, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/fiverr_clone_db'  # Replace with your MongoDB URI
mongo = PyMongo(app)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    #  validation
    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    if not is_valid_email(email): #Add validation
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
        #  In a real app, you'd create a session here using Flask-Login or similar
        return jsonify({'success': True, 'message': 'User created successfully', 'user_id': str(user_id)}), 201
    except Exception as e:
        print(f"Error creating user: {e}")
        return jsonify({'success': False, 'message': 'Failed to create user'}), 500

def is_valid_email(email):
    import re
    return re.match(r"^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$", email) is not None


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    user = mongo.db.users.find_one({'email': email})

    if user and check_password_hash(user['password'], password):
        #  In a real app, you'd create a session here
        return jsonify({'success': True, 'message': 'Logged in successfully', 'user_id': str(user['_id'])}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/dashboard')
def dashboard():
    #  This is just a placeholder.  You'd normally render a template here.
    return "Welcome to the Dashboard!"

if __name__ == '__main__':
    app.run(debug=True)
