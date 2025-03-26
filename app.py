# Import necessary libraries
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash # Added flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from bson import errors as bson_errors # Import BSON errors
from functools import wraps
import re
import datetime
import stripe  # Import the Stripe library
import os      # Import os to access environment variables
import traceback # For detailed exception logging

# --- Flask App Configuration ---
app = Flask(__name__)
# Ensure the MONGO_URI is correct and the user has write permissions
app.config['MONGO_URI'] = 'mongodb+srv://0p3nbullet:aiJ7QYL75t5pu0mo@prophetdice.8605b.mongodb.net/fiverr_clone_db?retryWrites=true&w=majority' # Added retryWrites and w=majority
# IMPORTANT: Use a strong, random secret key and store it securely
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_super_secret_key_for_dev_use_env_var_in_prod')
mongo = PyMongo(app)

# --- Stripe Configuration ---
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
# stripe_publishable_key = os.environ.get('STRIPE_PUBLISHABLE_KEY')

# --- Helper Functions ---

# Decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next_url'] = request.url
            flash('Please log in to access this page.', 'warning') # Add flash message
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is not None

# --- Routes ---

@app.route('/')
def index():
    user_id = session.get('user_id')
    user = None
    if user_id:
        try:
            user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
        except bson_errors.InvalidId:
            # Handle case where session contains invalid user_id
            session.pop('user_id', None)
            print("Warning: Invalid user_id found in session during index load.")
        except Exception as e:
            print(f"Error fetching user for index: {e}")
            # Proceed without user info
    current_year = datetime.datetime.now().year # Pass current year to template
    return render_template('index.html', user=user, current_year=current_year)

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'GET':
        # Redirect if already logged in? Optional.
        # if 'user_id' in session:
        #    return redirect(url_for('dashboard'))
        return render_template('signup.html')

    if request.method == 'POST':
        data = request.form
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')

        # Server-side validation (more robust than just client-side)
        error = None
        if not name: error = 'Full Name is required.'
        elif not email: error = 'Email is required.'
        elif not is_valid_email(email): error = 'Invalid email format.'
        elif not password: error = 'Password is required.'
        elif len(password) < 6: error = 'Password must be at least 6 characters.'
        elif not role: error = 'Account Type is required.'
        elif role not in ['user', 'seller']: error = 'Invalid Account Type specified.'

        if error:
            flash(error, 'danger') # Use flash for errors on page reload
            return render_template('signup.html', name=name, email=email, role=role), 400 # Pass back submitted data

        # Check if email exists
        if mongo.db.users.find_one({'email': email}):
            flash('Email address already exists. Please log in or use a different email.', 'warning')
            return render_template('signup.html', name=name, email=email, role=role), 400

        hashed_password = generate_password_hash(password)
        user_data = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': role,
            'balance': 0.0,
            'created_at': datetime.datetime.utcnow()
        }

        try:
            user_id = mongo.db.users.insert_one(user_data).inserted_id
            session['user_id'] = str(user_id) # Log the user in immediately
            flash(f'Welcome, {name}! Your account has been created.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"!!! Error creating user in DB: {e}")
            traceback.print_exc()
            flash('Failed to create account due to a server error. Please try again later.', 'danger')
            return render_template('signup.html', name=name, email=email, role=role), 500

    return "Method Not Allowed", 405


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        # if 'user_id' in session:
        #    return redirect(url_for('dashboard'))
        return render_template('login.html')

    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('login.html', email=email), 400

        user = mongo.db.users.find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            flash(f'Welcome back, {user["name"]}!', 'success')
            next_url = session.pop('next_url', None)
            return redirect(next_url or url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            return render_template('login.html', email=email), 401

    return "Method Not Allowed", 405


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('next_url', None)
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id'] # No need for .get() due to @login_required
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
    except (bson_errors.InvalidId, Exception) as e:
         print(f"Error fetching dashboard user data (ID: {user_id}): {e}")
         # Log user out if their ID is suddenly invalid
         session.pop('user_id', None)
         flash("There was an issue retrieving your data. Please log in again.", "error")
         return redirect(url_for('login_page'))

    if not user:
        session.pop('user_id', None)
        flash("Your user account could not be found. Please log in again.", "error")
        return redirect(url_for('login_page'))

    # Initialize data containers
    gigs = []
    sales = [] # Seller's sales (from purchases collection)
    purchased_gigs_list = [] # User's purchases (with gig details)
    purchased_automations_list = [] # User's automation purchases (with details)

    try:
        object_user_id = ObjectId(user_id) # Convert once for queries

        if user['role'] == 'seller':
            gigs = list(mongo.db.gigs.find({'seller_id': object_user_id}).sort('created_at', -1))
            # Fetch sales (purchases where this user is the seller)
            sales = list(mongo.db.purchases.find({'seller_id': object_user_id}).sort('purchase_date', -1))
            # You might want to fetch buyer/gig details for the sales list here if needed for display

        elif user['role'] == 'user':
            # Fetch gigs purchased by the user
            user_purchases_raw = list(mongo.db.purchases.find({'buyer_id': object_user_id}).sort('purchase_date', -1))
            gig_ids = [p['gig_id'] for p in user_purchases_raw if 'gig_id' in p]
            if gig_ids:
                purchased_gigs_details = list(mongo.db.gigs.find({'_id': {'$in': gig_ids}}))
                gigs_map = {g['_id']: g for g in purchased_gigs_details} # Use ObjectId as key
                for p in user_purchases_raw:
                    p['gig_details'] = gigs_map.get(p.get('gig_id')) # Get using ObjectId
                purchased_gigs_list = user_purchases_raw # Now contains details

            # Fetch automations purchased by the user (example structure)
            user_auto_purchases_raw = list(mongo.db.automation_purchases.find({'buyer_id': object_user_id}).sort('purchase_date', -1))
            automation_ids = [p['automation_id'] for p in user_auto_purchases_raw if 'automation_id' in p]
            if automation_ids:
                purchased_autos_details = list(mongo.db.automations.find({'_id': {'$in': automation_ids}}))
                autos_map = {a['_id']: a for a in purchased_autos_details}
                for p in user_auto_purchases_raw:
                    p['automation_details'] = autos_map.get(p.get('automation_id'))
                purchased_automations_list = user_auto_purchases_raw

    except Exception as e:
        print(f"Error fetching dashboard list data for user {user_id}: {e}")
        flash("Could not load all dashboard details due to an error.", "warning")
        # Continue rendering with potentially empty lists

    # Note: Pass distinct variables for clarity in the template
    return render_template('dashboard.html',
                           user=user,
                           seller_gigs=gigs, # Renamed for clarity
                           seller_sales=sales, # Renamed for clarity
                           user_purchased_gigs=purchased_gigs_list, # Renamed for clarity
                           user_purchased_automations=purchased_automations_list # Renamed for clarity
                           )


@app.route('/gigs/create', methods=['GET', 'POST'])
@login_required
def create_gig_page():
    """
    Handles GET request for the create gig form and POST request for creating a gig.
    Only accessible to sellers. Includes robust error handling for DB insert.
    """
    user_id = session['user_id']
    try:
        # Fetch user data again to ensure role hasn't changed (optional, but safer)
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    except Exception as e:
         print(f"Error fetching user {user_id} in create_gig_page: {e}")
         flash("An error occurred retrieving your user data.", "error")
         return redirect(url_for('dashboard'))


    if not user:
        session.pop('user_id', None)
        flash("Your user account could not be found.", "error")
        return redirect(url_for('login_page'))

    if user['role'] != 'seller':
        flash('Only sellers can create gigs.', 'warning')
        return redirect(url_for('dashboard'))

    # --- GET Request ---
    if request.method == 'GET':
        return render_template('create_gig.html', user=user) # Pass user if template needs it

    # --- POST Request Handling ---
    if request.method == 'POST':
        print("\n--- [POST /gigs/create] Received request ---")
        data = request.form
        title = data.get('title', '').strip() # Add strip()
        description = data.get('description', '').strip()
        price_str = data.get('price')
        category = data.get('category', '').strip()
        print(f"Form data received: title='{title}', price='{price_str}', category='{category}'")

        # --- Server-side Validation ---
        error_message = None
        price = None # Initialize price
        if not title: error_message = 'Gig Title is required.'
        elif not description: error_message = 'Description is required.'
        elif not price_str: error_message = 'Price is required.'
        elif not category: error_message = 'Category is required.'
        else:
            try:
                price = float(price_str)
                # Use a reasonable minimum, like $5 as in Fiverr
                if price < 5.00:
                    error_message = 'Price must be at least $5.00.'
            except ValueError:
                error_message = 'Invalid price format. Please enter a number (e.g., 25.50).'

        if error_message:
            print(f"Validation failed: {error_message}")
            flash(error_message, 'danger') # Use flash for page reload
            # Pass submitted data back to template to repopulate form
            return render_template('create_gig.html', user=user, error=error_message,
                                   form_title=title, form_description=description,
                                   form_price=price_str, form_category=category), 400
        # --- End Validation ---

        print("Validation passed.")
        seller_id_obj = ObjectId(user_id) # Use the validated user_id ObjectId

        gig_data = {
            'seller_id': seller_id_obj,
            'title': title,
            'description': description,
            'price': price, # Use the validated float price
            'category': category,
            'status': 'active', # Initial status
            'created_at': datetime.datetime.utcnow()
        }
        print(f"Prepared gig data for insertion: {gig_data}")

        # --- Database Insertion with Error Handling ---
        try:
            print("Attempting mongo.db.gigs.insert_one...")
            insert_result = mongo.db.gigs.insert_one(gig_data)

            if insert_result.acknowledged:
                gig_id = insert_result.inserted_id
                print(f"SUCCESS: Gig inserted successfully. Inserted ID: {gig_id}")
                flash('Gig created successfully!', 'success')
                print("Redirecting to dashboard...")
                # IMPORTANT: Only redirect AFTER successful acknowledged insert
                return redirect(url_for('dashboard'))
            else:
                # If not acknowledged (rare but possible)
                print("!!! ERROR: Insert operation not acknowledged by MongoDB.")
                flash('Failed to create gig: Database did not confirm the save operation.', 'danger')
                return render_template('create_gig.html', user=user, error='Database did not confirm save.',
                                       form_title=title, form_description=description,
                                       form_price=price_str, form_category=category), 500

        except Exception as e:
            # Catch PyMongo errors (e.g., connection, auth, validation) or others
            print(f"!!! DATABASE INSERTION FAILED in /gigs/create !!!")
            print(f"Error Type: {type(e)}")
            print(f"Error Args: {e.args}")
            print(f"Full Exception: {e}")
            traceback.print_exc() # Log full traceback to console
            # Provide a user-friendly error and log the details
            flash(f'Failed to create gig due to a server error. Please try again or contact support.', 'danger')
            return render_template('create_gig.html', user=user, error='Database save failed. Please try again.',
                                    form_title=title, form_description=description,
                                    form_price=price_str, form_category=category), 500
        # --- End Database Insertion ---

    return "Method Not Allowed", 405 # Fallback for methods other than GET/POST


# Added detailed logging and error handling to view_gig
@app.route('/gigs/<gig_id>')
def view_gig(gig_id):
    """
    Displays a single gig page. Includes logging and specific error handling.
    """
    print(f"--- [GET /gigs/{gig_id}] Attempting to view gig ---")
    print(f"Received raw gig_id from URL: '{gig_id}' (Type: {type(gig_id)})")

    try:
        object_id = ObjectId(gig_id)
        print(f"Successfully converted to ObjectId: {object_id}")

        gig = mongo.db.gigs.find_one({'_id': object_id})
        print(f"Result from database find_one: {'Found' if gig else 'None'}")

        if not gig:
            print(f"Gig not found in DB for ObjectId: {object_id}")
            flash('The requested gig could not be found.', 'warning')
            # Redirect to a more general page or show a specific "not found" template
            return render_template('404.html', message=f"Gig with ID {gig_id} not found."), 404 # Assuming you have 404.html

        # If gig found, proceed
        seller = mongo.db.users.find_one({'_id': gig['seller_id']}, {'password': 0})
        if not seller:
             print(f"Warning: Seller not found for gig {gig_id} (Seller ID: {gig['seller_id']})")
             # Decide how to handle - show gig anyway?

        # Determine if the current user can purchase
        session_user_id = session.get('user_id')
        current_user = None
        can_purchase = False
        if session_user_id:
             try:
                 current_user = mongo.db.users.find_one({'_id': ObjectId(session_user_id)}, {'password': 0})
                 if current_user and str(current_user['_id']) != str(gig['seller_id']) and gig['status'] == 'active':
                     can_purchase = True
             except (bson_errors.InvalidId, Exception) as user_fetch_error:
                 print(f"Error fetching current user {session_user_id} in view_gig: {user_fetch_error}")
                 # Proceed without purchase capability if user fetch fails

        print(f"Rendering view_gig.html for gig: {gig['_id']}")
        return render_template('view_gig.html', gig=gig, seller=seller, user=current_user, can_purchase=can_purchase)

    except bson_errors.InvalidId:
        print(f"!!! BSON InvalidId Error: '{gig_id}' is not a valid ObjectId format.")
        flash('The provided Gig ID format is invalid.', 'danger')
        # Redirect or show 404/error page
        return render_template('404.html', message="Invalid Gig ID format."), 400

    except Exception as e:
        print(f"!!! An unexpected error occurred in view_gig for ID '{gig_id}': {e}")
        traceback.print_exc() # Log full traceback
        flash('An error occurred while retrieving the gig details.', 'danger')
        # Redirect or show 500 error page
        return render_template('500.html', error=e), 500 # Assuming you have 500.html

# --- Payment Processing ---
# (Keep the Stripe routes as they were, they seem okay)
# process_stripe_payment function (potentially unused, consider removing if confirm_funding handles all)
# fund_account_page route
# create_payment_intent route
# confirm_funding route

# --- Purchase Logic ---
# (Keep the internal purchase routes as they were)
# purchase_gig route
# view_purchases route
# view_saas_automations route
# purchase_automation route


# --- API Endpoint for Sales (Example) ---
@app.route('/api/sales')
@login_required
def api_get_sales():
    """ API endpoint to fetch sales for the logged-in seller. """
    user_id = session['user_id']
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'role': 1})
        if not user or user.get('role') != 'seller':
             return jsonify({'success': False, 'message': 'Access denied: Not a seller.'}), 403

        # Find purchases where the current user is the seller
        sales_data = list(mongo.db.purchases.find({'seller_id': ObjectId(user_id)}).sort('purchase_date', -1))

        # Enhance data if needed (e.g., fetch buyer name, gig title)
        # Be mindful of performance if fetching many related documents
        sales_list = []
        # Example: Fetching related data (can be optimized)
        buyer_ids = list(set(s['buyer_id'] for s in sales_data)) # Unique buyer IDs
        gig_ids = list(set(s['gig_id'] for s in sales_data))     # Unique gig IDs
        buyers = {b['_id']: b for b in mongo.db.users.find({'_id': {'$in': buyer_ids}}, {'name': 1})} if buyer_ids else {}
        gigs = {g['_id']: g for g in mongo.db.gigs.find({'_id': {'$in': gig_ids}}, {'title': 1})} if gig_ids else {}

        for sale in sales_data:
            buyer_info = buyers.get(sale['buyer_id'])
            gig_info = gigs.get(sale['gig_id'])
            sales_list.append({
                'purchase_id': str(sale['_id']),
                'buyer_id': str(sale['buyer_id']),
                'buyer_name': buyer_info.get('name', 'N/A') if buyer_info else 'N/A',
                'gig_id': str(sale['gig_id']),
                'gig_title': gig_info.get('title', 'N/A') if gig_info else 'N/A',
                'price': sale['price'],
                'purchase_date': sale['purchase_date'].isoformat() + 'Z',
                'status': sale.get('status', 'completed')
            })

        return jsonify({'success': True, 'sales': sales_list})

    except bson_errors.InvalidId:
         return jsonify({'success': False, 'message': 'Invalid user ID format.'}), 400
    except Exception as e:
         print(f"Error in /api/sales for user {user_id}: {e}")
         traceback.print_exc()
         return jsonify({'success': False, 'message': 'An error occurred while fetching sales data.'}), 500


# --- Error Handlers (Optional but recommended) ---
@app.errorhandler(404)
def page_not_found(e):
    # Note: the view_gig route now renders 404.html directly for specific cases
    return render_template('404.html', message="Sorry, the page you requested was not found."), 404

@app.errorhandler(500)
def internal_server_error(e):
    # Log the error e
    print(f"Caught 500 error: {e}")
    traceback.print_exc()
    return render_template('500.html', error=e), 500

# Create basic 404.html and 500.html templates in your templates folder


# --- Main Execution ---
if __name__ == '__main__':
    # Ensure Stripe key is set before starting
    if not stripe.api_key:
        print("\n" + "="*60)
        print(" WARNING: Stripe Secret Key (STRIPE_SECRET_KEY) is not set.")
        print(" Stripe functionality MAY BE disabled depending on usage.")
        print(" Please set the environment variable and restart the server if needed.")
        print("="*60 + "\n")
    # Set host='0.0.0.0' to be accessible externally (e.g., in Docker)
    # debug=True is useful for development, should be False in production
    app.run(host='0.0.0.0', port=5000, debug=True)
