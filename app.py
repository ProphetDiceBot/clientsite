# --- START OF FILE app.py ---

# Import necessary libraries
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
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

# IMPORTANT: Use environment variables for sensitive data like MONGO_URI in production
# Example: mongodb+srv://<username>:<password>@cluster.mongodb.net/myDatabase?retryWrites=true&w=majority
# Avoid hardcoding credentials directly in the code.
app.config['MONGO_URI'] = os.environ.get(
    'MONGO_URI',
    'mongodb+srv://0p3nbullet:aiJ7QYL75t5pu0mo@prophetdice.8605b.mongodb.net/fiverr_clone_db?retryWrites=true&w=majority'
)
# IMPORTANT: Use a strong, random secret key and store it securely via environment variables
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_fallback_weak_secret_key_change_for_prod') # Use a better fallback or none
if app.secret_key == 'dev_fallback_weak_secret_key_change_for_prod' and not app.debug:
     print("\n" + "="*60)
     print(" WARNING: Using fallback FLASK_SECRET_KEY in non-debug mode!")
     print(" Please set a strong FLASK_SECRET_KEY environment variable.")
     print("="*60 + "\n")

mongo = PyMongo(app)

# --- Stripe Configuration ---
# IMPORTANT: Set these via environment variables in production
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
stripe_publishable_key = os.environ.get('STRIPE_PUBLISHABLE_KEY')

# --- Database Index Recommendation ---
# For improved query performance, consider creating indexes in your MongoDB shell:
# db.users.createIndex({ email: 1 }, { unique: true })
# db.gigs.createIndex({ seller_id: 1 })
# db.gigs.createIndex({ category: 1 })
# db.purchases.createIndex({ buyer_id: 1 })
# db.purchases.createIndex({ seller_id: 1 })
# db.purchases.createIndex({ gig_id: 1 })
# db.automation_purchases.createIndex({ buyer_id: 1 }) # If using automations

# --- CSRF Protection Recommendation ---
# Consider adding Flask-WTF for CSRF protection on forms
# from flask_wtf.csrf import CSRFProtect
# csrf = CSRFProtect(app)


# --- Helper Functions ---

# Decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next_url'] = request.url # Save intended URL
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login_page'))
        # Optional: Verify user_id still exists in DB here for extra security?
        # user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        # if not user:
        #     session.clear()
        #     flash('Your session is invalid. Please log in again.', 'error')
        #     return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def is_valid_email(email):
    """ Basic email format validation """
    # A more comprehensive regex might be needed for edge cases
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is not None

# --- Routes ---

@app.route('/')
def index():
    user_id = session.get('user_id')
    user = None
    if user_id:
        try:
            user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0}) # Exclude password
        except bson_errors.InvalidId:
            # Handle case where session contains invalid user_id
            session.pop('user_id', None)
            session.pop('next_url', None) # Clear related session data
            print(f"Warning: Invalid user_id '{user_id}' found in session during index load. Cleared session.")
        except Exception as e:
            print(f"Error fetching user '{user_id}' for index: {e}")
            # Proceed without user info, or flash an error?
    current_year = datetime.datetime.now().year # Pass current year to template
    return render_template('index.html', user=user, current_year=current_year)

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'GET':
        if 'user_id' in session:
           # Optional: Redirect if already logged in
           flash("You are already logged in.", "info")
           return redirect(url_for('dashboard'))
        return render_template('signup.html') # Pass empty context for GET

    if request.method == 'POST':
        # Check if request is JSON or form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower() # Store email in lowercase
        password = data.get('password') # Don't strip password
        role = data.get('role')

        # --- Server-side Validation ---
        errors = {}
        if not name: errors['name'] = 'Full Name is required.'
        if not email: errors['email'] = 'Email is required.'
        elif not is_valid_email(email): errors['email'] = 'Invalid email format.'
        if not password: errors['password'] = 'Password is required.'
        elif len(password) < 6: errors['password'] = 'Password must be at least 6 characters long.'
        if not role: errors['role'] = 'Account Type is required.'
        elif role not in ['user', 'seller']: errors['role'] = 'Invalid Account Type specified.'

        # Check if email already exists *before* hashing password etc.
        if not errors.get('email'):
            try:
                if mongo.db.users.find_one({'email': email}):
                    errors['email'] = 'Email address already registered. Please log in or use a different email.'
            except Exception as e:
                print(f"Error checking existing email '{email}': {e}")
                errors['general'] = 'Could not verify email availability. Please try again.'


        if errors:
            # Decide response format based on request type
            if request.is_json:
                 # Combine errors for a single message or return structured errors
                 error_message = ". ".join(errors.values())
                 return jsonify({'success': False, 'message': error_message, 'errors': errors}), 400
            else:
                 # Flash individual errors or a combined message
                 combined_error_msg = "Please correct the errors below: " + ". ".join(errors.values())
                 flash(combined_error_msg, 'danger')
                 # Pass submitted data back to template
                 return render_template('signup.html',
                                        form_name=name, form_email=email, form_role=role,
                                        errors=errors), 400

        # --- Proceed with User Creation ---
        hashed_password = generate_password_hash(password)
        user_data = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': role,
            'balance': 0.00, # Ensure float
            'created_at': datetime.datetime.utcnow()
            # Add other fields: profile_pic_url, description, etc. later
        }

        try:
            insert_result = mongo.db.users.insert_one(user_data)
            if insert_result.acknowledged:
                user_id = insert_result.inserted_id
                session['user_id'] = str(user_id) # Log the user in immediately
                session.pop('next_url', None) # Clear any saved redirect URL
                flash(f'Welcome, {name}! Your account has been created successfully.', 'success')
                if request.is_json:
                    # For AJAX, return success and let JS handle redirect
                    return jsonify({'success': True, 'message': 'Account created.', 'redirect_url': url_for('dashboard')}), 201 # 201 Created
                else:
                    # For standard form submission, redirect
                    return redirect(url_for('dashboard'))
            else:
                 # Should not happen with default write concern but handle defensively
                 raise Exception("Database did not acknowledge the insert operation.")

        except Exception as e:
            print(f"!!! Database Error creating user '{email}': {e}")
            traceback.print_exc()
            error_message = 'Failed to create account due to a server error. Please try again later.'
            if request.is_json:
                 return jsonify({'success': False, 'message': error_message}), 500
            else:
                 flash(error_message, 'danger')
                 # Pass back data again
                 return render_template('signup.html',
                                        form_name=name, form_email=email, form_role=role,
                                        errors={'general': error_message}), 500

    # If method is not GET or POST
    return "Method Not Allowed", 405


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        if 'user_id' in session:
           flash("You are already logged in.", "info")
           return redirect(url_for('dashboard'))
        next_url = request.args.get('next') # Allow redirect back after login
        if next_url:
            session['next_url'] = next_url
        return render_template('login.html')

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        email = data.get('email', '').strip().lower()
        password = data.get('password')
        # remember = data.get('remember') # Handle 'remember me' if needed

        error_message = None
        if not email or not password:
            error_message = 'Email and password are required.'

        user = None
        if not error_message:
            try:
                user = mongo.db.users.find_one({'email': email})
            except Exception as e:
                 print(f"Error fetching user for login '{email}': {e}")
                 error_message = "An error occurred during login. Please try again."

        if not error_message and user and check_password_hash(user['password'], password):
            # Login successful
            session['user_id'] = str(user['_id'])
            # session.permanent = bool(remember) # Set session cookie duration if using 'remember me'
            flash(f'Welcome back, {user["name"]}!', 'success')
            next_url = session.pop('next_url', None) # Get saved redirect URL

            if request.is_json:
                return jsonify({'success': True, 'message': 'Login successful.', 'redirect_url': next_url or url_for('dashboard')}), 200
            else:
                return redirect(next_url or url_for('dashboard'))
        else:
            # Login failed
            if not error_message: # Only set if not already set by DB error etc.
                 error_message = 'Invalid email or password.'

            if request.is_json:
                 return jsonify({'success': False, 'message': error_message}), 401 # Unauthorized
            else:
                 flash(error_message, 'danger')
                 return render_template('login.html', email=email), 401 # Render page again with error

    return "Method Not Allowed", 405


@app.route('/logout')
def logout():
    user_id = session.pop('user_id', None)
    session.pop('next_url', None)
    # session.clear() # Use clear() to remove everything if needed
    if user_id:
        flash('You have been successfully logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id'] # Guaranteed by @login_required
    user = None
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
    except bson_errors.InvalidId:
         print(f"CRITICAL: Invalid user_id '{user_id}' in session for logged-in user. Logging out.")
         session.clear()
         flash("Your session was invalid. Please log in again.", "error")
         return redirect(url_for('login_page'))
    except Exception as e:
         print(f"Error fetching dashboard user data (ID: {user_id}): {e}")
         # Don't log out immediately, maybe temporary DB issue, show limited dashboard?
         flash("There was an issue retrieving some of your data.", "warning")
         # Proceeding, user object might be None

    if not user:
        # If user is None after try/except, means find_one failed or ID didn't exist
        print(f"CRITICAL: User account not found for logged-in user_id '{user_id}'. Logging out.")
        session.clear()
        flash("Your user account could not be found. Please log in again.", "error")
        return redirect(url_for('login_page'))

    # Initialize data containers (will be loaded via AJAX, but keep structure for initial render)
    seller_gigs = []
    # seller_sales = [] # Loaded via AJAX
    # user_purchased_gigs = [] # Loaded via AJAX
    # user_purchased_automations = [] # Loaded via AJAX

    try:
        object_user_id = ObjectId(user_id) # Convert once

        if user['role'] == 'seller':
            # Fetch seller's gigs for initial display
            seller_gigs = list(mongo.db.gigs.find({'seller_id': object_user_id}).sort('created_at', -1))
            # Sales will be fetched via /api/sales AJAX call

        # elif user['role'] == 'user':
            # Purchases will be fetched via /purchases AJAX call (if implemented)

    except Exception as e:
        print(f"Error fetching initial dashboard list data for user {user_id}: {e}")
        traceback.print_exc()
        flash("Could not load initial dashboard details due to an error.", "warning")
        # Continue rendering with potentially empty lists

    return render_template('dashboard.html',
                           user=user,
                           gigs=seller_gigs, # Pass gigs for seller's initial view
                           # Pass other initially loaded data if any
                           )

@app.route('/gigs/create', methods=['GET', 'POST'])
@login_required
def create_gig_page():
    """
    Handles GET request for the create gig form and POST request for creating a gig.
    Only accessible to sellers. Includes robust error handling for DB insert.
    """
    user_id = session['user_id']
    user = None
    try:
        # Fetch user data again to ensure role hasn't changed and user exists
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
    except (bson_errors.InvalidId, Exception) as e:
         print(f"Error fetching user {user_id} in create_gig_page: {e}")
         flash("An error occurred retrieving your user data. Please try again.", "error")
         # Log out if critical ID error
         if isinstance(e, bson_errors.InvalidId): session.clear()
         return redirect(url_for('login_page' if isinstance(e, bson_errors.InvalidId) else 'dashboard'))

    if not user:
        session.clear() # Log out if user not found
        flash("Your user account could not be found. Please log in again.", "error")
        return redirect(url_for('login_page'))

    if user['role'] != 'seller':
        flash('Only sellers can create gigs.', 'warning')
        return redirect(url_for('dashboard'))

    # --- GET Request ---
    if request.method == 'GET':
        # Pass empty form data initially or data from previous failed attempt if stored in session
        form_data = session.pop('create_gig_form_data', {})
        errors = session.pop('create_gig_errors', {})
        return render_template('create_gig.html', user=user, **form_data, errors=errors)

    # --- POST Request Handling ---
    if request.method == 'POST':
        print("\n--- [POST /gigs/create] Received request ---")
        data = request.form
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        price_str = data.get('price')
        category = data.get('category', '').strip()
        # Add image handling later: image_file = request.files.get('image')
        print(f"Form data received: title='{title}', price='{price_str}', category='{category}'")

        # --- Server-side Validation ---
        errors = {}
        price = None # Initialize price
        if not title: errors['title'] = 'Gig Title is required.'
        elif len(title) > 100: errors['title'] = 'Title cannot exceed 100 characters.'
        if not description: errors['description'] = 'Description is required.'
        if not category: errors['category'] = 'Category is required.'
        if not price_str: errors['price'] = 'Price is required.'
        else:
            try:
                price = round(float(price_str), 2) # Round to 2 decimal places
                # Use a reasonable minimum, like $5.00 as in Fiverr
                if price < 5.00:
                    errors['price'] = 'Price must be at least $5.00.'
                elif price > 10000.00: # Example maximum
                    errors['price'] = 'Price seems too high (max $10,000.00).'
            except ValueError:
                errors['price'] = 'Invalid price format. Please enter a number (e.g., 25.50).'
        # Add image validation here if implementing uploads

        if errors:
            print(f"Validation failed: {errors}")
            flash("Please correct the errors below.", 'danger')
            # Store data and errors in session to repopulate form via GET redirect (Post/Redirect/Get pattern)
            # session['create_gig_form_data'] = data.to_dict() # Store immutable dict
            # session['create_gig_errors'] = errors
            # return redirect(url_for('create_gig_page'))
            # OR Render directly (simpler for now, but loses data on refresh)
            return render_template('create_gig.html', user=user, errors=errors,
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
            'status': 'active', # Initial status: 'active', 'pending_approval', etc.
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow()
            # Add default/placeholder values for fields from view_gig.html if needed now
            # 'image_url': None, # Add image handling later
            # 'rating': 0,
            # 'review_count': 0,
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
                return redirect(url_for('dashboard')) # PRG Pattern
            else:
                # If not acknowledged (rare but possible)
                print("!!! ERROR: Insert operation not acknowledged by MongoDB.")
                raise Exception("Database did not confirm the save operation.")

        except Exception as e:
            # Catch PyMongo errors (e.g., connection, auth, validation) or others
            print(f"!!! DATABASE INSERTION FAILED in /gigs/create !!!")
            print(f"Error Type: {type(e)}")
            print(f"Error Args: {e.args}")
            print(f"Full Exception: {e}")
            traceback.print_exc() # Log full traceback to console
            # Provide a user-friendly error and log the details
            flash(f'Failed to create gig due to a server error. Please try again or contact support.', 'danger')
            # Render directly with error
            return render_template('create_gig.html', user=user,
                                    errors={'general': 'Database save failed. Please try again.'},
                                    form_title=title, form_description=description,
                                    form_price=price_str, form_category=category), 500
        # --- End Database Insertion ---

    return "Method Not Allowed", 405 # Fallback for methods other than GET/POST


@app.route('/gigs/<gig_id>')
def view_gig(gig_id):
    """
    Displays a single gig page. Includes logging and specific error handling.
    """
    print(f"--- [GET /gigs/{gig_id}] Attempting to view gig ---")
    gig = None
    seller = None
    current_user = None
    can_purchase = False

    try:
        object_id = ObjectId(gig_id)
        print(f"Successfully converted to ObjectId: {object_id}")

        gig = mongo.db.gigs.find_one({'_id': object_id})
        print(f"Result from database find_one: {'Found' if gig else 'None'}")

        if not gig:
            print(f"Gig not found in DB for ObjectId: {object_id}")
            flash('The requested gig could not be found.', 'warning')
            return render_template('404.html', message=f"Gig with ID {gig_id} not found."), 404

        # If gig found, fetch seller
        seller = mongo.db.users.find_one({'_id': gig['seller_id']}, {'password': 0})
        if not seller:
             print(f"Warning: Seller not found for gig {gig_id} (Seller ID: {gig['seller_id']})")
             # Decide how to handle - show gig anyway? For now, yes, but template should handle missing seller.

        # Determine if the current user can purchase
        session_user_id = session.get('user_id')
        if session_user_id:
             try:
                 # Need ObjectId conversion for comparison
                 session_user_object_id = ObjectId(session_user_id)
                 # Check if viewer is not the seller AND gig is active
                 if session_user_object_id != gig['seller_id'] and gig.get('status', 'inactive') == 'active':
                     can_purchase = True
                 # Fetch current user details if needed by the template (optional)
                 current_user = mongo.db.users.find_one({'_id': session_user_object_id}, {'password': 0})

             except bson_errors.InvalidId:
                 print(f"Warning: Invalid user_id '{session_user_id}' in session while viewing gig {gig_id}. Cannot determine purchase capability.")
                 session.clear() # Log out user with invalid session ID
             except Exception as user_fetch_error:
                 print(f"Error fetching current user {session_user_id} in view_gig: {user_fetch_error}")
                 # Proceed without purchase capability if user fetch fails

        print(f"Rendering view_gig.html for gig: {gig['_id']}")
        # Ensure default values for potentially missing fields used in template
        gig.setdefault('image_url', 'https://via.placeholder.com/400x200/cccccc/ffffff?text=No+Image')
        gig.setdefault('rating', 0)
        gig.setdefault('review_count', 0)

        return render_template('view_gig.html',
                               gig=gig,
                               seller=seller,
                               user=current_user, # Pass current user object
                               can_purchase=can_purchase) # Pass purchase flag

    except bson_errors.InvalidId:
        print(f"!!! BSON InvalidId Error: '{gig_id}' is not a valid ObjectId format.")
        flash('The provided Gig ID format is invalid.', 'danger')
        return render_template('404.html', message="Invalid Gig ID format."), 400

    except Exception as e:
        print(f"!!! An unexpected error occurred in view_gig for ID '{gig_id}': {e}")
        traceback.print_exc() # Log full traceback
        flash('An error occurred while retrieving the gig details.', 'danger')
        return render_template('500.html', error=str(e)), 500 # Pass error string

# --- Payment Processing ---

@app.route('/fund-account', methods=['GET'])
@login_required
def fund_account_page():
    """ Displays the page for adding funds using Stripe. """
    user_id = session['user_id']
    user = None
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
    except (bson_errors.InvalidId, Exception) as e:
         print(f"Error fetching user {user_id} for fund_account_page: {e}")
         flash("An error occurred retrieving your data.", "error")
         if isinstance(e, bson_errors.InvalidId): session.clear()
         return redirect(url_for('login_page' if isinstance(e, bson_errors.InvalidId) else 'dashboard'))

    if not user:
         session.clear()
         flash("Your user account could not be found.", "error")
         return redirect(url_for('login_page'))

    if not stripe_publishable_key:
         flash("Payment processing is currently unavailable due to configuration issues.", "warning")
         # Still render page but show config issue message in template

    return render_template('fund_account.html',
                           user=user,
                           stripe_key=stripe_publishable_key,
                           error=None) # Pass None for error initially


@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment_intent():
    """ Creates a Stripe Payment Intent """
    if not stripe.api_key:
        return jsonify({'error': 'Payment processing not configured.'}), 503

    user_id = session['user_id']
    try:
        data = request.get_json()
        amount_str = data.get('amount')
        if not amount_str:
            return jsonify({'error': 'Amount is required.'}), 400

        # Validate amount server-side
        try:
            amount_float = float(amount_str)
            # Stripe expects amount in cents (smallest currency unit)
            amount_cents = int(round(amount_float * 100))
            if amount_cents < 50: # Minimum $0.50
                 return jsonify({'error': 'Amount must be at least $0.50.'}), 400
            # Add a reasonable maximum if desired
            # if amount_cents > 1000000: # Max $10,000
            #     return jsonify({'error': 'Maximum funding amount exceeded.'}), 400

        except ValueError:
            return jsonify({'error': 'Invalid amount format.'}), 400

        # Fetch user email for Stripe metadata/receipts (optional but good)
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'email': 1})
        customer_email = user.get('email') if user else None

        # Create a PaymentIntent with the order amount and currency
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency='usd',
            # In the latest version of the API, specifying the `automatic_payment_methods` parameter
            # is optional because Stripe enables its functionality by default.
            automatic_payment_methods={'enabled': True},
            metadata={
                'user_id': user_id,
                'funding_type': 'account_balance'
            },
            receipt_email=customer_email # Optional: Stripe sends email receipt
        )
        return jsonify({
            'clientSecret': intent.client_secret
        })

    except stripe.error.StripeError as e:
        print(f"Stripe Error creating PaymentIntent for user {user_id}: {e}")
        return jsonify({'error': f'Stripe Error: {e.user_message or str(e)}'}), 500
    except Exception as e:
        print(f"Error creating PaymentIntent for user {user_id}: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Failed to initialize payment session.'}), 500


@app.route('/confirm-funding', methods=['POST'])
@login_required
def confirm_funding():
    """ Confirms the payment intent and updates user balance. """
    if not stripe.api_key:
        return jsonify({'success': False, 'message': 'Payment processing not configured.'}), 503

    user_id = session['user_id']
    data = request.get_json()
    payment_intent_id = data.get('payment_intent_id')

    if not payment_intent_id:
        return jsonify({'success': False, 'message': 'Payment Intent ID missing.'}), 400

    try:
        # Retrieve the PaymentIntent from Stripe to verify its status
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)

        # Basic check: Does the intent belong to this funding operation? (using metadata)
        if intent.metadata.get('user_id') != user_id or intent.metadata.get('funding_type') != 'account_balance':
             print(f"Security Alert: Payment Intent {payment_intent_id} metadata mismatch for user {user_id}.")
             # Don't reveal too much info in the error message
             return jsonify({'success': False, 'message': 'Payment confirmation failed (metadata mismatch).'}), 400

        # Check if the PaymentIntent status is 'succeeded'
        if intent.status == 'succeeded':
            amount_funded_cents = intent.amount_received # Amount actually captured
            amount_funded_dollars = float(amount_funded_cents) / 100.0

            # --- Idempotency Check ---
            # Prevent processing the same successful payment multiple times.
            # Check if this payment_intent_id has already been processed and recorded.
            # Example: Store processed intent IDs in a separate collection or add a flag to the user/transaction record.
            # For simplicity here, we'll assume it's not processed yet, but add a TODO.
            # TODO: Implement idempotency check using a transactions collection or similar mechanism.
            # Example Check:
            # existing_txn = mongo.db.transactions.find_one({'payment_intent_id': payment_intent_id})
            # if existing_txn:
            #    print(f"Idempotency: Payment Intent {payment_intent_id} already processed for user {user_id}.")
            #    # Return success but indicate it was already done
            #    return jsonify({'success': True, 'message': f'Funding of ${amount_funded_dollars:.2f} already confirmed.'})

            # --- Update User Balance Securely ---
            # Use $inc for atomic update
            update_result = mongo.db.users.update_one(
                {'_id': ObjectId(user_id)},
                {
                    '$inc': {'balance': amount_funded_dollars},
                    '$set': {'updated_at': datetime.datetime.utcnow()} # Optionally track updates
                }
            )

            if update_result.matched_count == 1 and update_result.modified_count == 1:
                print(f"User {user_id} balance updated by ${amount_funded_dollars:.2f}")
                # TODO: Record this transaction in a dedicated 'transactions' collection for history/auditing.
                # mongo.db.transactions.insert_one({
                #    'user_id': ObjectId(user_id),
                #    'type': 'funding',
                #    'amount': amount_funded_dollars,
                #    'payment_intent_id': payment_intent_id,
                #    'status': 'completed',
                #    'timestamp': datetime.datetime.utcnow()
                # })
                return jsonify({'success': True, 'message': f'Successfully added ${amount_funded_dollars:.2f} to your account!'})
            elif update_result.matched_count == 1 and update_result.modified_count == 0:
                 # This could happen if the amount was 0, or potentially a DB state issue
                 print(f"Warning: User {user_id} balance update matched but not modified for intent {payment_intent_id}.")
                 return jsonify({'success': True, 'message': f'Funding confirmed, but balance not changed (Amount: ${amount_funded_dollars:.2f}).'})
            else:
                 # Critical: User not found or update failed
                 print(f"CRITICAL: Failed to update balance for user {user_id} after successful payment {payment_intent_id}.")
                 # Need manual investigation/reconciliation process
                 return jsonify({'success': False, 'message': 'Payment confirmed, but failed to update account balance. Please contact support.'}), 500

        elif intent.status == 'processing':
             # This shouldn't usually happen with card payments after confirmCardPayment succeeds
             return jsonify({'success': False, 'message': 'Payment is still processing. Please wait a moment and refresh.'}), 402 # Payment Required (or 202 Accepted)
        else:
             # Handle other statuses like 'requires_payment_method', 'failed', etc.
             print(f"Payment Intent {payment_intent_id} has status: {intent.status}")
             return jsonify({'success': False, 'message': f'Payment confirmation failed. Status: {intent.status}.'}), 400

    except stripe.error.StripeError as e:
        print(f"Stripe Error confirming PaymentIntent {payment_intent_id} for user {user_id}: {e}")
        return jsonify({'success': False, 'message': f'Stripe Error: {e.user_message or str(e)}'}), 500
    except bson_errors.InvalidId:
         print(f"CRITICAL: Invalid user_id '{user_id}' in session during funding confirmation.")
         session.clear()
         return jsonify({'success': False, 'message': 'Invalid session. Please log in again.'}), 401
    except Exception as e:
        print(f"Error confirming funding for user {user_id}, intent {payment_intent_id}: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'An internal error occurred during funding confirmation.'}), 500


# --- Purchase Logic (Placeholders - Implement These) ---

# @app.route('/gigs/<gig_id>/purchase', methods=['POST']) # Example POST route
@app.route('/gigs/<gig_id>/purchase') # GET for simplicity now, should be POST
@login_required
def purchase_gig(gig_id):
    """ Placeholder: Handles the purchase of a gig. """
    user_id = session['user_id']
    try:
        gig_object_id = ObjectId(gig_id)
        gig = mongo.db.gigs.find_one({'_id': gig_object_id})
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

        if not gig:
             flash("Gig not found.", "error")
             return redirect(url_for('index'))
        if not user:
             session.clear()
             flash("User not found.", "error")
             return redirect(url_for('login_page'))

        # 1. Check if purchasable (not own gig, active status, etc.)
        if str(gig['seller_id']) == user_id:
             flash("You cannot purchase your own gig.", "warning")
             return redirect(url_for('view_gig', gig_id=gig_id))
        if gig.get('status') != 'active':
            flash("This gig is currently not available for purchase.", "warning")
            return redirect(url_for('view_gig', gig_id=gig_id))

        # 2. Check user balance
        gig_price = gig.get('price', 0.0)
        if user.get('balance', 0.0) < gig_price:
            flash(f"Insufficient balance. You need ${gig_price:.2f}, but have ${user['balance']:.2f}. Please add funds.", "warning")
            return redirect(url_for('fund_account_page')) # Redirect to funding page

        # 3. *** Critical Section: Atomically deduct balance, add to seller (maybe escrow later), record purchase ***
        # This should ideally be a single atomic transaction if possible, or carefully ordered operations with rollback/reconciliation.
        # Simple (non-atomic, risky) approach:
        try:
            # Deduct from buyer
            update_buyer = mongo.db.users.update_one(
                {'_id': ObjectId(user_id), 'balance': {'$gte': gig_price}}, # Ensure balance hasn't changed
                {'$inc': {'balance': -gig_price}}
            )
            if update_buyer.modified_count == 0:
                raise Exception("Failed to deduct buyer balance (Insufficient funds or concurrent modification).")

            # Add to seller (Or to an escrow balance initially)
            update_seller = mongo.db.users.update_one(
                {'_id': gig['seller_id']},
                {'$inc': {'balance': gig_price}} # Direct transfer for now
            )
            if update_seller.modified_count == 0:
                 # Rollback buyer deduction if seller update fails? Complex.
                 print(f"CRITICAL: Failed to credit seller {gig['seller_id']} after deducting from buyer {user_id}.")
                 # Attempt rollback (best effort)
                 mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$inc': {'balance': gig_price}})
                 raise Exception("Failed to credit seller balance.")

            # Record the purchase
            purchase_data = {
                'buyer_id': ObjectId(user_id),
                'seller_id': gig['seller_id'],
                'gig_id': gig_object_id,
                'price': gig_price,
                'purchase_date': datetime.datetime.utcnow(),
                'status': 'completed' # Or 'in_progress', 'pending_delivery' etc.
            }
            mongo.db.purchases.insert_one(purchase_data)

            # Optionally update gig status (e.g., if it's a single-instance gig)
            # mongo.db.gigs.update_one({'_id': gig_object_id}, {'$set': {'status': 'sold'}})

            flash(f"Successfully purchased '{gig['title']}'!", "success")
            return redirect(url_for('dashboard')) # Redirect to user's dashboard/purchases

        except Exception as purchase_error:
            print(f"Error during purchase process for gig {gig_id}, user {user_id}: {purchase_error}")
            traceback.print_exc()
            # Rollback attempts might be needed here depending on where the failure occurred.
            flash(f"An error occurred during purchase: {purchase_error}. Please try again or contact support.", "danger")
            return redirect(url_for('view_gig', gig_id=gig_id))

    except bson_errors.InvalidId:
        flash("Invalid Gig or User ID.", "error")
        return redirect(url_for('index'))
    except Exception as e:
        print(f"General error in purchase_gig {gig_id}: {e}")
        flash("An unexpected error occurred.", "danger")
        return redirect(url_for('index'))


# @app.route('/purchases') # GET - For AJAX call from dashboard
@app.route('/purchases', methods=['GET'])
@login_required
def view_purchases():
    """ API endpoint to fetch purchases for the logged-in user. """
    user_id = session['user_id']
    purchases_list = []

    try:
        buyer_object_id = ObjectId(user_id)
        # Find purchases made by the current user
        user_purchases_raw = list(mongo.db.purchases.find({'buyer_id': buyer_object_id}).sort('purchase_date', -1))

        # Enhance data with Gig titles (optimize by fetching necessary IDs first)
        gig_ids = list(set(p['gig_id'] for p in user_purchases_raw if 'gig_id' in p))
        gigs_map = {}
        if gig_ids:
            gigs_details = list(mongo.db.gigs.find({'_id': {'$in': gig_ids}}, {'title': 1, 'seller_id': 1})) # Fetch title and seller_id
            gigs_map = {g['_id']: g for g in gigs_details}

            # Optional: Fetch seller names if needed
            # seller_ids = list(set(g['seller_id'] for g in gigs_details))
            # sellers_map = {s['_id']: s['name'] for s in mongo.db.users.find({'_id': {'$in': seller_ids}}, {'name': 1})}

        for p in user_purchases_raw:
            gig_detail = gigs_map.get(p.get('gig_id'))
            # seller_name = sellers_map.get(gig_detail['seller_id']) if gig_detail and 'seller_id' in gig_detail else 'N/A'
            purchases_list.append({
                'purchase_id': str(p['_id']),
                'gig_id': str(p.get('gig_id')),
                'item_title': gig_detail.get('title', 'Gig Title Missing') if gig_detail else 'N/A',
                # 'seller_name': seller_name,
                'price': p.get('price', 0.0),
                'purchase_date': p.get('purchase_date').isoformat() + 'Z' if p.get('purchase_date') else None,
                'status': p.get('status', 'unknown')
            })

        # TODO: Add logic for fetching purchased automations if that feature exists
        # user_auto_purchases_raw = list(mongo.db.automation_purchases.find(...))
        # ... similar enhancement logic ...

        return jsonify({'success': True, 'purchases': purchases_list})

    except bson_errors.InvalidId:
         return jsonify({'success': False, 'message': 'Invalid user ID format.'}), 400
    except Exception as e:
         print(f"Error in /purchases API for user {user_id}: {e}")
         traceback.print_exc()
         return jsonify({'success': False, 'message': 'An error occurred while fetching purchase data.'}), 500


# @app.route('/automations')
# def view_saas_automations():
#     # Placeholder: Fetch and display available automations
#     return "SaaS Automations Page (Not Implemented)"

# @app.route('/automations/<automation_id>/purchase')
# @login_required
# def purchase_automation(automation_id):
#     # Placeholder: Handle purchase of automation
#     return f"Purchase Automation {automation_id} (Not Implemented)"

# --- API Endpoint for Sales (Example) ---
@app.route('/api/sales')
@login_required
def api_get_sales():
    """ API endpoint to fetch sales for the logged-in seller. """
    user_id = session['user_id']
    try:
        user_object_id = ObjectId(user_id)
        user = mongo.db.users.find_one({'_id': user_object_id}, {'role': 1})

        if not user:
             return jsonify({'success': False, 'message': 'User not found.'}), 404 # Or 401/403
        if user.get('role') != 'seller':
             return jsonify({'success': False, 'message': 'Access denied: Not a seller.'}), 403

        # Find purchases where the current user is the seller
        sales_data = list(mongo.db.purchases.find({'seller_id': user_object_id}).sort('purchase_date', -1))

        # Enhance data (fetch buyer name, gig title) - Optimized approach
        sales_list = []
        if sales_data:
            buyer_ids = list(set(s['buyer_id'] for s in sales_data))
            gig_ids = list(set(s['gig_id'] for s in sales_data))

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
                    'price': sale.get('price', 0.0),
                    'purchase_date': sale.get('purchase_date').isoformat() + 'Z' if sale.get('purchase_date') else None,
                    'status': sale.get('status', 'completed') # Reflect actual purchase status
                })

        return jsonify({'success': True, 'sales': sales_list})

    except bson_errors.InvalidId:
         # This case might indicate an issue with the session user_id if user fetch failed earlier
         return jsonify({'success': False, 'message': 'Invalid user ID format in session.'}), 400
    except Exception as e:
         print(f"Error in /api/sales for user {user_id}: {e}")
         traceback.print_exc()
         return jsonify({'success': False, 'message': 'An error occurred while fetching sales data.'}), 500


# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    # Log the error or the path requested
    print(f"404 Not Found: {request.path} - Error: {e}")
    # You can return JSON if the request Accept header prefers it
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
         return jsonify(error=str(e), message="Resource not found"), 404
    return render_template('404.html', message=f"Sorry, the page '{request.path}' was not found."), 404

@app.errorhandler(405)
def method_not_allowed(e):
    print(f"405 Method Not Allowed: {request.method} for {request.path} - Error: {e}")
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify(error=str(e), message=f"Method {request.method} not allowed for this resource."), 405
    # Consider a specific 405 template or reuse 404/500
    return render_template('404.html', message=f"Method {request.method} is not allowed for this page."), 405


@app.errorhandler(500)
@app.errorhandler(Exception) # Catch general exceptions too
def internal_server_error(e):
    # Log the actual exception object e
    print(f"500 Internal Server Error: {request.path} - Error: {e}")
    traceback.print_exc() # Log the full traceback

    # Important: Avoid exposing detailed internal errors to the user in production
    error_message_for_user = "Sorry, something went wrong on our end. Please try again later."

    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
         return jsonify(error="Internal Server Error", message=error_message_for_user), 500

    # Pass a generic error message to the template unless in debug mode
    error_to_show = str(e) if app.debug else error_message_for_user
    return render_template('500.html', error=error_to_show), 500


# --- Main Execution ---
if __name__ == '__main__':
    # Check for essential configurations at startup
    if not app.config['MONGO_URI'] or '0p3nbullet:aiJ7QYL75t5pu0mo' in app.config['MONGO_URI']:
         print("\n" + "="*60)
         print(" WARNING: MONGO_URI seems misconfigured or using default credentials.")
         print(" Please set the MONGO_URI environment variable correctly.")
         print("="*60 + "\n")

    stripe_ok = True
    if not stripe.api_key:
        print("\n" + "="*60)
        print(" WARNING: Stripe Secret Key (STRIPE_SECRET_KEY) is not set.")
        print(" Stripe payment creation/confirmation WILL FAIL.")
        print(" Please set the environment variable and restart.")
        print("="*60 + "\n")
        stripe_ok = False
    if not stripe_publishable_key:
        print("\n" + "="*60)
        print(" WARNING: Stripe Publishable Key (STRIPE_PUBLISHABLE_KEY) is not set.")
        print(" Stripe checkout form WILL NOT RENDER correctly.")
        print(" Please set the environment variable and restart.")
        print("="*60 + "\n")
        stripe_ok = False

    # Set host='0.0.0.0' to be accessible externally (e.g., in Docker)
    # debug=True is useful for development, should be False in production
    print(f"Starting Flask server... Debug mode: {app.debug}")
    app.run(host='0.0.0.0', port=5000, debug=app.debug) # Use app.debug setting
