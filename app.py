from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from functools import wraps
import re  # Import the regular expression module
import datetime  # Import datetime

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
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None



@app.route('/')
def index():
    """
    This route renders the main HTML page.
    """
    return render_template('index.html')
##

@app.route('/signup', methods=['POST'])
def signup():
    """
    Handles user registration (signup).
    """
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')  # New field to specify the role (user or seller)

    # Validation
    if not name or not email or not password or not role:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    if not is_valid_email(email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400
    if role not in ['user', 'seller']:
        return jsonify({'success': False, 'message': 'Invalid role specified'}), 400

    # Check if the email is already taken
    if mongo.db.users.find_one({'email': email}):
        return jsonify({'success': False, 'message': 'Email already exists'}), 400

    hashed_password = generate_password_hash(password)
    user_data = {
        'name': name,
        'email': email,
        'password': hashed_password,
        'role': role,  # Store the role in the user data
        'balance': 0.0  # Initialize user balance
    }

    try:
        user_id = mongo.db.users.insert_one(user_data).inserted_id
        session['user_id'] = str(user_id)  # Set the user_id in the session
        return jsonify({'success': True, 'message': 'User created successfully'}), 201
    except Exception as e:
        print(f"Error creating user: {e}")
        return jsonify({'success': False, 'message': 'Failed to create user'}), 500
##

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
    Renders the dashboard page.  Now passes user data.
    """
    user_id = session.get('user_id')
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if user:
        # Fetch gigs created by the user
        gigs = mongo.db.gigs.find({'seller_id': ObjectId(user_id)})
        # Fetch SaaS automations
        automations = mongo.db.automations.find()
        return render_template('dashboard.html', user=user, gigs=gigs, automations=automations)  # Pass user and gigs data to the template
    else:
        return redirect(url_for('login'))

@app.route('/create_gig', methods=['POST'])
@login_required
def create_gig():
    """
    Handles the creation of a new gig.
    """
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    price = data.get('price')
    category = data.get('category') # added category

    if not title or not description or not price or not category: # added category
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    try:
        price = float(price)  # Convert price to float
        if price <= 0:
            return jsonify({'success': False, 'message': 'Price must be greater than zero'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid price format'}), 400

    seller_id = ObjectId(session['user_id'])
    gig_data = {
        'seller_id': seller_id,
        'title': title,
        'description': description,
        'price': price,
        'category': category, # added category
        'status': 'active'  # Set the initial status of the gig
    }

    try:
        gig_id = mongo.db.gigs.insert_one(gig_data).inserted_id
        return jsonify({'success': True, 'message': 'Gig created successfully', 'gig_id': str(gig_id)}), 201
    except Exception as e:
        print(f"Error creating gig: {e}")
        return jsonify({'success': False, 'message': 'Failed to create gig'}), 500
    
# Placeholder for Stripe/Poof.io integration
def process_payment(amount, token, payment_method):
    """
    Placeholder function to simulate processing payment with Stripe/Poof.io.
    Replace this with actual integration code.
    """
    print(f"Processing {payment_method} payment of ${amount} with token: {token}")
    #  Add actual Stripe or Poof.io API calls here
    if payment_method == 'stripe':
        #  Stripe API call
        pass
    elif payment_method == 'poof':
        #  Poof.io API call
        pass
    
    return {'success': True, 'transaction_id': 'txn_' + str(ObjectId())} #  Return a dummy transaction ID

@app.route('/fund_account', methods=['POST'])
@login_required
def fund_account():
    """
    Handles funding the user's account using Stripe/Poof.io.
    """
    data = request.get_json()
    amount = data.get('amount')
    token = data.get('token')  #  Payment token from frontend
    payment_method = data.get('payment_method') # "stripe" or "poof"

    if not amount or not token or not payment_method:
        return jsonify({'success': False, 'message': 'Amount, token, and payment method are required'}), 400
    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be greater than zero'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount format'}), 400

    user_id = ObjectId(session['user_id'])
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Process payment
    payment_result = process_payment(amount, token, payment_method) #  Call placeholder

    if not payment_result['success']:
        return jsonify({'success': False, 'message': 'Payment failed'}), 400 #  Adjust status code if necessary

    new_balance = user['balance'] + amount
    try:
        mongo.db.users.update_one({'_id': user_id}, {'$set': {'balance': new_balance}})
        return jsonify({'success': True, 'message': f'Account funded successfully. New balance: ${new_balance}', 'transaction_id': payment_result['transaction_id']}), 200
    except Exception as e:
        print(f"Error funding account: {e}")
        return jsonify({'success': False, 'message': 'Failed to fund account'}), 500
    
@app.route('/purchase_gig', methods=['POST'])
@login_required
def purchase_gig():
    """
    Handles the purchase of a gig.
    """
    data = request.get_json()
    gig_id = data.get('gig_id')

    if not gig_id:
        return jsonify({'success': False, 'message': 'Gig ID is required'}), 400

    try:
        gig_id = ObjectId(gig_id)
    except:
        return jsonify({'success': False, 'message': 'Invalid gig ID format'}), 400

    gig = mongo.db.gigs.find_one({'_id': gig_id})
    if not gig:
        return jsonify({'success': False, 'message': 'Gig not found'}), 404

    if gig['status'] != 'active':
        return jsonify({'success': False, 'message': 'Gig is not active'}), 400

    buyer_id = ObjectId(session['user_id'])
    buyer = mongo.db.users.find_one({'_id': buyer_id})
    if not buyer:
        return jsonify({'success': False, 'message': 'Buyer not found'}), 404

    if buyer['balance'] < gig['price']:
        return jsonify({'success': False, 'message': 'Insufficient funds'}), 400

    # Update buyer's balance
    new_balance = buyer['balance'] - gig['price']
    try:
        mongo.db.users.update_one({'_id': buyer_id}, {'$set': {'balance': new_balance}})
    except Exception as e:
        print(f"Error updating buyer balance: {e}")
        return jsonify({'success': False, 'message': 'Failed to update buyer balance'}), 500

    # Record the purchase
    purchase_data = {
        'buyer_id': buyer_id,
        'gig_id': gig_id,
        'seller_id': gig['seller_id'], #add seller id
        'purchase_date': datetime.utcnow(),
        'price': gig['price'],
        'status': 'pending'  # Initial status of the purchase
    }
    try:
        purchase_id = mongo.db.purchases.insert_one(purchase_data).inserted_id
    except Exception as e:
        print(f"Error recording purchase: {e}")
        return jsonify({'success': False, 'message': 'Failed to record purchase'}), 500
    
    # Update gig status to 'sold'
    try:
        mongo.db.gigs.update_one({'_id': gig_id}, {'$set': {'status': 'sold'}})
    except Exception as e:
        print(f"Error updating gig status: {e}")
        return jsonify({'success': False, 'message': 'Failed to update gig status'}), 500

    return jsonify({'success': True, 'message': 'Gig purchased successfully', 'purchase_id': str(purchase_id)}), 200

@app.route('/purchases')
@login_required
def view_purchases():
    """
    View all purchases made by the user.
    """
    user_id = session.get('user_id')
    purchases = mongo.db.purchases.find({'buyer_id': ObjectId(user_id)})
    purchase_list = []
    for purchase in purchases:
        # Get gig details for each purchase
        gig = mongo.db.gigs.find_one({'_id': purchase['gig_id']})
        if gig:
            purchase_data = {
                'purchase_id': str(purchase['_id']),
                'gig_title': gig['title'],
                'price': purchase['price'],
                'purchase_date': purchase['purchase_date'],
                'status': purchase['status']
            }
            purchase_list.append(purchase_data)
    return jsonify({'success': True, 'purchases': purchase_list}), 200



@app.route('/saas_automations')
@login_required
def view_saas_automations():
    """
    View available SaaS automations.
    """
    automations = mongo.db.automations.find()  # Fetch all automations from the database
    automation_list = []
    for automation in automations:
        automation_list.append({
            'id': str(automation['_id']),
            'title': automation['title'],
            'description': automation['description'],
            'price': automation['price']
        })
    return jsonify({'success': True, 'automations': automation_list}), 200

@app.route('/purchase_automation', methods=['POST'])
@login_required
def purchase_automation():
    """
    Handles the purchase of a SaaS automation.
    """
    data = request.get_json()
    automation_id = data.get('automation_id')

    if not automation_id:
        return jsonify({'success': False, 'message': 'Automation ID is required'}), 400

    try:
        automation_id = ObjectId(automation_id)
    except:
        return jsonify({'success': False, 'message': 'Invalid automation ID format'}), 400

    automation = mongo.db.automations.find_one({'_id': automation_id})
    if not automation:
        return jsonify({'success': False, 'message': 'Automation not found'}), 404

    user_id = ObjectId(session['user_id'])
    user = mongo.db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if user['balance'] < automation['price']:
        return jsonify({'success': False, 'message': 'Insufficient funds'}), 400

    # Update buyer's balance
    new_balance = user['balance'] - automation['price']
    try:
        mongo.db.users.update_one({'_id': user_id}, {'$set': {'balance': new_balance}})
    except Exception as e:
        print(f"Error updating buyer balance: {e}")
        return jsonify({'success': False, 'message': 'Failed to update buyer balance'}), 500

    # Record the automation purchase
    purchase_data = {
        'buyer_id': user_id,
        'automation_id': automation_id,
        'purchase_date': datetime.utcnow(),
        'price': automation['price'],
        'status': 'pending', # initial status
    }
    try:
        purchase_id = mongo.db.automation_purchases.insert_one(purchase_data).inserted_id
    except Exception as e:
        print(f"Error recording automation purchase: {e}")
        return jsonify({'success': False, 'message': 'Failed to record automation purchase'}), 500

    return jsonify({'success': True, 'message': 'Automation purchased successfully', 'purchase_id': str(purchase_id)}), 200



@app.route('/dashboard')
@login_required
def dashboard():
    """
    Renders the dashboard page. Now passes user data.
    """
    user_id = session.get('user_id')
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if user:
        if user['role'] != 'seller':
            return jsonify({'success': False, 'message': 'Access denied: You do not have the required role'}), 403
        # Fetch gigs created by the user
        gigs = mongo.db.gigs.find({'seller_id': ObjectId(user_id)})
        # Fetch SaaS automations
        automations = mongo.db.automations.find()
        return render_template('dashboard.html', user=user, gigs=gigs, automations=automations)  # Pass user and gigs data to the template
    else:
        return redirect(url_for('login'))
    

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
