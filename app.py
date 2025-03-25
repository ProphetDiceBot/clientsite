# Import necessary libraries
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from functools import wraps
import re
import datetime
import stripe  # Import the Stripe library
import os      # Import os to access environment variables

# --- Flask App Configuration ---
app = Flask(__name__)
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb+srv://0p3nbullet:aiJ7QYL75t5pu0mo@prophetdice.8605b.mongodb.net/fiverr_clone_db')
# IMPORTANT: Use a strong, random secret key and store it securely (e.g., environment variable)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_super_secret_key_for_dev') # Use environment variable or a fallback
mongo = PyMongo(app)

# --- Stripe Configuration ---
# IMPORTANT: Store your Stripe keys securely as environment variables
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY') # Your Stripe secret key
# Make sure you have a STRIPE_PUBLISHABLE_KEY environment variable set for your frontend
# stripe_publishable_key = os.environ.get('STRIPE_PUBLISHABLE_KEY') # Not used directly in backend, but good practice

# --- Helper Functions ---

# Decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Store the intended URL in session before redirecting to login
            session['next_url'] = request.url
            # You might want to flash a message here or return a JSON error for API calls
            return redirect(url_for('login_page')) # Redirect to a GET route for login page
        return f(*args, **kwargs)
    return decorated_function

def is_valid_email(email):
    """
    Validates the email format using a regular expression.
    """
    # Basic regex, consider using a more robust library if needed
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is not None

# --- Routes ---

@app.route('/')
def index():
    """
    Renders the main landing/index page.
    """
    # You might want to pass logged-in status or user info here
    user_id = session.get('user_id')
    user = None
    if user_id:
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0}) # Exclude password
    return render_template('index.html', user=user)

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    """
    Handles GET requests for the signup page and POST requests for signup logic.
    """
    if request.method == 'GET':
        return render_template('signup.html') # Assuming you have a signup.html

    if request.method == 'POST':
        # Prefer request.form for standard form submissions, request.get_json() for JSON APIs
        data = request.form # Changed to request.form assuming standard form post
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role') # user or seller

        # Validation
        if not name or not email or not password or not role:
            # Consider flashing messages instead of returning JSON for HTML forms
            return render_template('signup.html', error='All fields are required'), 400
        if not is_valid_email(email):
            return render_template('signup.html', error='Invalid email format'), 400
        if role not in ['user', 'seller']:
            return render_template('signup.html', error='Invalid role specified'), 400

        # Check if the email is already taken
        if mongo.db.users.find_one({'email': email}):
            return render_template('signup.html', error='Email already exists'), 400

        hashed_password = generate_password_hash(password)
        user_data = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': role,
            'balance': 0.0, # Initialize user balance
            'created_at': datetime.datetime.utcnow() # Add creation timestamp
        }

        try:
            user_id = mongo.db.users.insert_one(user_data).inserted_id
            session['user_id'] = str(user_id) # Log the user in immediately
            # Redirect to dashboard or a success page
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Error creating user: {e}")
            # Log the error properly
            return render_template('signup.html', error='Failed to create user. Please try again.'), 500

    # Default return if method is not GET or POST (though Flask handles this)
    return "Method Not Allowed", 405


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """
    Handles GET requests for the login page and POST requests for login logic.
    """
    if request.method == 'GET':
        return render_template('login.html') # Assuming you have a login.html

    if request.method == 'POST':
        # Prefer request.form for standard form submissions
        data = request.form # Changed to request.form
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return render_template('login.html', error='Email and password are required'), 400

        user = mongo.db.users.find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id']) # Set the user_id in the session
            # Redirect to the originally intended page or dashboard
            next_url = session.pop('next_url', None)
            return redirect(next_url or url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials'), 401

    # Default return if method is not GET or POST
    return "Method Not Allowed", 405


@app.route('/logout')
def logout():
    """
    Handles user logout.
    """
    session.pop('user_id', None) # Clear the user session
    session.pop('next_url', None) # Clear any stored redirect URL
    # Flash a success message (optional)
    # flash('You have been logged out.', 'success')
    return redirect(url_for('index')) # Redirect to home page

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Renders the dashboard page, showing relevant info based on user role.
    """
    user_id = session['user_id'] # No need for .get() due to @login_required
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0}) # Exclude password

    if not user:
        # This case should ideally not happen if @login_required works, but good to handle
        session.pop('user_id', None)
        return redirect(url_for('login_page'))

    gigs = []
    automations = []
    purchased_gigs = []
    purchased_automations = []
    sales = []

    if user['role'] == 'seller':
        # Fetch gigs created by the seller
        gigs = list(mongo.db.gigs.find({'seller_id': ObjectId(user_id)}))
        # Fetch sales made by the seller
        sales = list(mongo.db.purchases.find({'seller_id': ObjectId(user_id)}))
        # Potentially fetch created automations if sellers can create them
        # automations = list(mongo.db.automations.find({'creator_id': ObjectId(user_id)}))

    elif user['role'] == 'user':
        # Fetch gigs purchased by the user
        user_purchases = list(mongo.db.purchases.find({'buyer_id': ObjectId(user_id)}))
        gig_ids = [p['gig_id'] for p in user_purchases]
        if gig_ids:
             purchased_gigs_details = list(mongo.db.gigs.find({'_id': {'$in': gig_ids}}))
             # Map details back to purchases
             gigs_map = {str(g['_id']): g for g in purchased_gigs_details}
             for p in user_purchases:
                 p['gig_details'] = gigs_map.get(str(p['gig_id']))
             purchased_gigs = user_purchases

        # Fetch automations purchased by the user
        user_auto_purchases = list(mongo.db.automation_purchases.find({'buyer_id': ObjectId(user_id)}))
        automation_ids = [p['automation_id'] for p in user_auto_purchases]
        if automation_ids:
            purchased_autos_details = list(mongo.db.automations.find({'_id': {'$in': automation_ids}}))
            autos_map = {str(a['_id']): a for a in purchased_autos_details}
            for p in user_auto_purchases:
                p['automation_details'] = autos_map.get(str(p['automation_id']))
            purchased_automations = user_auto_purchases


    # Fetch all active SaaS automations for display (optional, could be on a separate page)
    # all_automations = list(mongo.db.automations.find({'status': 'active'})) # Assuming an active status

    return render_template('dashboard.html',
                           user=user,
                           gigs=gigs, # Seller's gigs
                           sales=sales, # Seller's sales
                           purchased_gigs=purchased_gigs, # User's purchased gigs
                           purchased_automations=purchased_automations # User's purchased automations
                           # automations=all_automations # All available automations (if needed here)
                           )


@app.route('/gigs/create', methods=['GET', 'POST'])
@login_required
def create_gig_page():
    """
    Handles GET request for the create gig form and POST request for creating a gig.
    Only accessible to sellers.
    """
    user_id = session['user_id']
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

    if not user or user['role'] != 'seller':
        # flash('You must be a seller to create gigs.', 'danger')
        return redirect(url_for('dashboard')) # Or a more specific error page/message

    if request.method == 'GET':
        # You might need to pass categories or other data for the form
        return render_template('create_gig.html') # Assuming create_gig.html template

    if request.method == 'POST':
        data = request.form # Assuming standard form post
        title = data.get('title')
        description = data.get('description')
        price_str = data.get('price')
        category = data.get('category')

        if not title or not description or not price_str or not category:
            return render_template('create_gig.html', error='All fields are required'), 400
        try:
            price = float(price_str)
            if price <= 0:
                return render_template('create_gig.html', error='Price must be positive'), 400
        except ValueError:
            return render_template('create_gig.html', error='Invalid price format'), 400

        seller_id = ObjectId(user_id)
        gig_data = {
            'seller_id': seller_id,
            'title': title,
            'description': description,
            'price': price,
            'category': category,
            'status': 'active', # Initial status
            'created_at': datetime.datetime.utcnow()
        }

        try:
            gig_id = mongo.db.gigs.insert_one(gig_data).inserted_id
            # flash('Gig created successfully!', 'success')
            return redirect(url_for('dashboard')) # Redirect to dashboard after creation
        except Exception as e:
            print(f"Error creating gig: {e}")
            # Log the error
            return render_template('create_gig.html', error='Failed to create gig'), 500

    return "Method Not Allowed", 405


@app.route('/gigs/<gig_id>')
def view_gig(gig_id):
    """
    Displays a single gig page.
    """
    try:
        gig = mongo.db.gigs.find_one({'_id': ObjectId(gig_id)})
        if not gig:
            return "Gig not found", 404

        seller = mongo.db.users.find_one({'_id': gig['seller_id']}, {'password': 0}) # Fetch seller details

        user_id = session.get('user_id')
        user = None
        can_purchase = False
        if user_id:
             user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
             # Check if user is logged in, is not the seller, and has enough balance (optional check here)
             if user and str(user['_id']) != str(gig['seller_id']) and gig['status'] == 'active':
                 can_purchase = True # Simplified check, balance check done at purchase time

        return render_template('view_gig.html', gig=gig, seller=seller, user=user, can_purchase=can_purchase)
    except Exception as e: # Catch invalid ObjectId format
        print(f"Error viewing gig {gig_id}: {e}")
        return "Invalid Gig ID", 400


# --- Payment Processing (Stripe Integration) ---

def process_stripe_payment(amount_cents, currency, payment_method_id, description):
    """
    Processes payment using Stripe PaymentIntents (more robust than Charges).
    amount_cents: Amount in the smallest currency unit (e.g., cents for USD).
    currency: Currency code (e.g., 'usd').
    payment_method_id: The ID from Stripe.js (e.g., 'pm_xyz').
    description: Description for the charge.
    """
    if not stripe.api_key:
        print("ERROR: Stripe API key is not configured.")
        return {'success': False, 'message': 'Payment processor not configured.'}

    try:
        # Create a PaymentIntent
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            payment_method=payment_method_id,
            confirm=True,  # Confirm the intent immediately
            automatic_payment_methods={ # Recommended for future-proofing
                'enabled': True,
                'allow_redirects': 'never' # Adjust if redirects are needed
            },
            description=description,
            # You might want to add metadata like user_id
            metadata={'user_id': session.get('user_id', 'unknown')}
        )

        # Handle post-payment confirmation steps if needed (e.g., 3D Secure)
        # For simplicity, we assume immediate success or failure here.
        # In a real app, check intent.status after creation/confirmation.
        # Statuses: 'succeeded', 'requires_action', 'processing', 'requires_payment_method', 'canceled'

        if intent.status == 'succeeded':
            return {'success': True, 'transaction_id': intent.id, 'charge_id': intent.latest_charge}
        elif intent.status == 'requires_action':
             # This shouldn't happen with allow_redirects='never', but handle defensively
             return {'success': False, 'message': 'Further action required to complete payment.', 'client_secret': intent.client_secret}
        else:
             # Handle other statuses ('requires_payment_method', 'processing', 'canceled')
            return {'success': False, 'message': f'Payment failed with status: {intent.status}'}

    except stripe.error.CardError as e:
        # Specific card error
        body = e.json_body
        err = body.get('error', {})
        print(f"Stripe Card Error: {e.user_message}")
        return {'success': False, 'message': err.get('message', 'Card declined.')}
    except stripe.error.StripeError as e:
        # Generic Stripe error
        print(f"Stripe Error: {e}")
        return {'success': False, 'message': 'Payment processing failed. Please try again.'}
    except Exception as e:
        # Other unexpected errors
        print(f"Unexpected error during payment: {e}")
        return {'success': False, 'message': 'An unexpected error occurred during payment.'}


@app.route('/fund', methods=['GET'])
@login_required
def fund_account_page():
    """ Renders the page for funding the account. """
    user_id = session['user_id']
    user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
    if not user:
        return redirect(url_for('login_page'))

    # Pass the Stripe Publishable Key to the template
    stripe_publishable_key = os.environ.get('STRIPE_PUBLISHABLE_KEY')
    if not stripe_publishable_key:
        print("WARNING: STRIPE_PUBLISHABLE_KEY is not set. Frontend Stripe.js might fail.")
        # You might want to disable funding if the key isn't set
        return render_template('fund_account.html', user=user, stripe_key=None, error="Payment gateway not configured correctly.")

    return render_template('fund_account.html', user=user, stripe_key=stripe_publishable_key)


@app.route('/create-payment-intent', methods=['POST'])
@login_required
def create_payment_intent():
    """ Creates a PaymentIntent for Stripe.js on the frontend """
    if not stripe.api_key:
         return jsonify({'error': 'Payment processor not configured.'}), 500

    try:
        data = request.get_json()
        amount = data.get('amount')

        if not amount:
            return jsonify({'error': 'Amount is required'}), 400
        try:
            amount_float = float(amount)
            if amount_float <= 0.50: # Stripe has minimum charge amounts (e.g., $0.50 USD)
                return jsonify({'error': 'Amount must be at least $0.50'}), 400
            amount_cents = int(amount_float * 100) # Convert to cents
        except ValueError:
            return jsonify({'error': 'Invalid amount format'}), 400

        user_id = session['user_id']

        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency='usd', # Or get from config/request
            automatic_payment_methods={'enabled': True},
            metadata={'user_id': user_id, 'purpose': 'Account Funding'}
        )
        return jsonify({
            'clientSecret': intent.client_secret
        })
    except stripe.error.StripeError as e:
        print(f"Stripe API Error creating PaymentIntent: {e}")
        return jsonify({'error': f'Stripe Error: {e}'}), 500
    except Exception as e:
        print(f"Error creating PaymentIntent: {e}")
        return jsonify({'error': 'Could not initiate payment session'}), 500


@app.route('/confirm-funding', methods=['POST'])
@login_required
def confirm_funding():
    """
    Confirms the funding after Stripe processes the PaymentIntent on the frontend.
    This endpoint is called *after* stripe.confirmCardPayment succeeds in JS.
    It primarily verifies the PaymentIntent status and updates the user's balance.
    """
    if not stripe.api_key:
         return jsonify({'success': False, 'message': 'Payment processor not configured.'}), 500

    data = request.get_json()
    payment_intent_id = data.get('payment_intent_id')

    if not payment_intent_id:
        return jsonify({'success': False, 'message': 'Payment Intent ID is required'}), 400

    try:
        # Retrieve the PaymentIntent from Stripe to verify its status
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)

        # Double-check the user ID if stored in metadata
        user_id_from_intent = intent.metadata.get('user_id')
        session_user_id = session['user_id']
        if user_id_from_intent != session_user_id:
             print(f"SECURITY WARNING: PaymentIntent user ID ({user_id_from_intent}) does not match session user ID ({session_user_id})")
             # Decide how to handle: reject, log, investigate
             return jsonify({'success': False, 'message': 'Payment confirmation mismatch.'}), 400

        # Check if the PaymentIntent was successful
        if intent.status == 'succeeded':
            amount_received_cents = intent.amount_received
            amount_received_dollars = amount_received_cents / 100.0

            # Prevent double crediting - check if this transaction was already processed
            # You might add a 'processed_payments' collection or a flag on the user/transaction record
            existing_tx = mongo.db.transactions.find_one({'stripe_payment_intent_id': payment_intent_id})
            if existing_tx:
                print(f"Warning: Funding for PaymentIntent {payment_intent_id} already processed.")
                # Return success but maybe indicate it was already done
                user = mongo.db.users.find_one({'_id': ObjectId(session_user_id)}, {'balance': 1})
                return jsonify({'success': True, 'message': f'Funding already confirmed. Current balance: ${user.get("balance", 0.0):.2f}'})


            # Update user balance
            user_id = ObjectId(session_user_id)
            update_result = mongo.db.users.update_one(
                {'_id': user_id},
                {'$inc': {'balance': amount_received_dollars}}
            )

            if update_result.modified_count == 1:
                 # Record the transaction
                transaction_data = {
                    'user_id': user_id,
                    'type': 'funding',
                    'amount': amount_received_dollars,
                    'currency': intent.currency,
                    'method': 'stripe',
                    'stripe_payment_intent_id': intent.id,
                    'stripe_charge_id': intent.latest_charge, # If available
                    'status': 'completed',
                    'timestamp': datetime.datetime.utcnow()
                }
                mongo.db.transactions.insert_one(transaction_data)

                # Get updated balance to return
                user = mongo.db.users.find_one({'_id': user_id}, {'balance': 1})
                new_balance = user.get('balance', 0.0)

                return jsonify({
                    'success': True,
                    'message': f'Account funded successfully with ${amount_received_dollars:.2f}. New balance: ${new_balance:.2f}',
                    'transaction_id': intent.id # Use PaymentIntent ID as transaction ID
                }), 200
            else:
                 # User not found or balance not updated - should be rare
                 print(f"Error: Failed to update balance for user {user_id} after successful payment {payment_intent_id}")
                 # You might need manual intervention here or retry logic
                 return jsonify({'success': False, 'message': 'Payment confirmed but failed to update account balance.'}), 500

        else:
            # PaymentIntent was not successful
            return jsonify({'success': False, 'message': f'Payment confirmation failed. Status: {intent.status}'}), 400

    except stripe.error.StripeError as e:
        print(f"Stripe API Error confirming payment: {e}")
        return jsonify({'success': False, 'message': f'Stripe Error: {e}'}), 500
    except Exception as e:
        print(f"Error confirming funding: {e}")
        return jsonify({'success': False, 'message': 'Failed to confirm funding'}), 500

# --- Purchase Logic ---

@app.route('/purchase/gig/<gig_id>', methods=['POST'])
@login_required
def purchase_gig(gig_id):
    """
    Handles the purchase of a gig using the user's internal balance.
    This is triggered *after* a user confirms they want to buy from the gig page.
    """
    try:
        gig_object_id = ObjectId(gig_id)
    except:
        return jsonify({'success': False, 'message': 'Invalid gig ID format'}), 400

    gig = mongo.db.gigs.find_one({'_id': gig_object_id})
    if not gig:
        return jsonify({'success': False, 'message': 'Gig not found'}), 404

    if gig['status'] != 'active':
        return jsonify({'success': False, 'message': 'This gig is no longer available for purchase'}), 400

    buyer_id = ObjectId(session['user_id'])
    buyer = mongo.db.users.find_one({'_id': buyer_id})
    if not buyer:
        # Should not happen if @login_required works
        return jsonify({'success': False, 'message': 'Buyer account not found'}), 404

    # Check if the buyer is also the seller
    if gig['seller_id'] == buyer_id:
         return jsonify({'success': False, 'message': 'You cannot purchase your own gig'}), 400


    gig_price = gig['price']
    if buyer['balance'] < gig_price:
        return jsonify({'success': False, 'message': 'Insufficient funds. Please fund your account.'}), 400

    # --- Perform the transaction ---
    # 1. Deduct balance from buyer
    buyer_update = mongo.db.users.update_one(
        {'_id': buyer_id, 'balance': {'$gte': gig_price}}, # Ensure balance hasn't changed concurrently
        {'$inc': {'balance': -gig_price}}
    )

    if buyer_update.modified_count == 0:
        # This could happen if balance check passed but update failed (e.g., race condition)
        return jsonify({'success': False, 'message': 'Purchase failed due to a balance issue. Please try again.'}), 409 # Conflict

    # 2. (Optional but recommended) Add funds to seller's balance *or* hold in escrow
    # Simple transfer:
    seller_update = mongo.db.users.update_one(
        {'_id': gig['seller_id']},
        {'$inc': {'balance': gig_price}} # You might take a platform fee here: * (1 - fee_rate)
    )
    if seller_update.modified_count == 0:
         # This is problematic - buyer was charged but seller wasn't paid.
         # Requires handling: Log error, potentially revert buyer charge, notify admin.
         print(f"CRITICAL ERROR: Failed to credit seller {gig['seller_id']} after buyer {buyer_id} purchased gig {gig_id}")
         # Attempt to refund buyer as a failsafe? Complex.
         # For now, inform buyer but log the inconsistency.
         return jsonify({'success': False, 'message': 'Purchase partially failed. Please contact support.'}), 500


    # 3. Record the purchase transaction
    purchase_data = {
        'buyer_id': buyer_id,
        'gig_id': gig_object_id,
        'seller_id': gig['seller_id'],
        'purchase_date': datetime.datetime.utcnow(),
        'price': gig_price,
        'status': 'completed', # Or 'pending_delivery' if there's a workflow
        'transaction_type': 'gig_purchase'
    }
    try:
        purchase_record = mongo.db.purchases.insert_one(purchase_data)
        purchase_id = purchase_record.inserted_id

        # 4. Update gig status (e.g., mark as sold or decrement quantity if applicable)
        # If a gig can only be sold once:
        mongo.db.gigs.update_one({'_id': gig_object_id}, {'$set': {'status': 'sold'}})
        # If multiple sales possible, maybe add buyer_id to a list or increment a counter

    except Exception as e:
        print(f"Error recording purchase or updating gig status for gig {gig_id}: {e}")
        # Critical: Payment transferred but record failed. Need robust logging/recovery.
        # Inform user, log error details.
        return jsonify({'success': False, 'message': 'Purchase recorded partially. Please contact support.'}), 500

    # Success
    # Fetch updated buyer balance to show
    updated_buyer = mongo.db.users.find_one({'_id': buyer_id}, {'balance': 1})
    new_balance = updated_buyer.get('balance', buyer['balance'] - gig_price) # Fallback calculation

    # flash('Gig purchased successfully!', 'success') # If redirecting
    return jsonify({
        'success': True,
        'message': f'Gig "{gig["title"]}" purchased successfully for ${gig_price:.2f}.',
        'purchase_id': str(purchase_id),
        'new_balance': f'{new_balance:.2f}'
        }), 200


@app.route('/purchases')
@login_required
def view_purchases():
    """
    API endpoint to view all purchases made by the logged-in user.
    Returns JSON data.
    """
    user_id = ObjectId(session['user_id'])
    # Find purchases where the user is the buyer
    user_purchases = list(mongo.db.purchases.find({'buyer_id': user_id}).sort('purchase_date', -1))

    purchase_list = []
    # Get related gig details efficiently
    gig_ids = [p['gig_id'] for p in user_purchases if 'gig_id' in p]
    if gig_ids:
        gigs = mongo.db.gigs.find({'_id': {'$in': gig_ids}})
        gigs_map = {str(g['_id']): g for g in gigs}

        for purchase in user_purchases:
            gig_detail = gigs_map.get(str(purchase.get('gig_id')))
            if gig_detail:
                purchase_data = {
                    'purchase_id': str(purchase['_id']),
                    'item_type': 'gig',
                    'item_title': gig_detail.get('title', 'N/A'),
                    'item_id': str(gig_detail['_id']),
                    'seller_id': str(gig_detail.get('seller_id')),
                    'price': purchase['price'],
                    'purchase_date': purchase['purchase_date'].isoformat() + 'Z', # ISO format UTC
                    'status': purchase['status']
                }
                purchase_list.append(purchase_data)
            else:
                 # Handle case where gig might be deleted but purchase record exists
                 print(f"Warning: Gig {purchase.get('gig_id')} not found for purchase {purchase['_id']}")


    # You could similarly fetch and add automation purchases here if needed
    # user_auto_purchases = list(mongo.db.automation_purchases.find(...))
    # ... logic to combine ...


    return jsonify({'success': True, 'purchases': purchase_list}), 200


# --- SaaS Automations (Placeholder/Example Structure) ---

# You would need routes similar to gigs for creating, viewing, and purchasing automations
# Example:
@app.route('/automations')
def view_saas_automations():
    """
    View available SaaS automations (example).
    """
    # Add pagination later if needed
    automations = list(mongo.db.automations.find({'status': 'active'}))
    for auto in automations: # Ensure ID is string for JSON
        auto['_id'] = str(auto['_id'])
        if 'creator_id' in auto: # Assuming a creator field
            auto['creator_id'] = str(auto['creator_id'])

    return jsonify({'success': True, 'automations': automations}), 200


@app.route('/purchase/automation/<automation_id>', methods=['POST'])
@login_required
def purchase_automation(automation_id):
    """
    Handles the purchase of a SaaS automation using internal balance (example).
    Very similar logic to purchase_gig.
    """
    try:
        automation_object_id = ObjectId(automation_id)
    except:
        return jsonify({'success': False, 'message': 'Invalid automation ID format'}), 400

    automation = mongo.db.automations.find_one({'_id': automation_object_id})
    if not automation:
        return jsonify({'success': False, 'message': 'Automation not found'}), 404

    # Add checks for automation status ('active'?)

    buyer_id = ObjectId(session['user_id'])
    buyer = mongo.db.users.find_one({'_id': buyer_id})
    if not buyer:
        return jsonify({'success': False, 'message': 'Buyer account not found'}), 404

    # Prevent self-purchase if applicable (depends on your model)
    # if automation.get('creator_id') == buyer_id:
    #     return jsonify({'success': False, 'message': 'You cannot purchase your own automation'}), 400

    automation_price = automation['price']
    if buyer['balance'] < automation_price:
        return jsonify({'success': False, 'message': 'Insufficient funds.'}), 400

    # --- Perform the transaction (similar to gig purchase) ---
    # 1. Deduct buyer balance
    buyer_update = mongo.db.users.update_one(
        {'_id': buyer_id, 'balance': {'$gte': automation_price}},
        {'$inc': {'balance': -automation_price}}
    )
    if buyer_update.modified_count == 0:
        return jsonify({'success': False, 'message': 'Purchase failed due to balance issue.'}), 409

    # 2. Credit seller/platform (handle potential errors)
    # Example: Direct credit to a creator/owner if exists
    creator_id = automation.get('creator_id')
    if creator_id:
        seller_update = mongo.db.users.update_one(
             {'_id': creator_id},
             {'$inc': {'balance': automation_price}} # Add fee deduction logic if needed
        )
        if seller_update.modified_count == 0:
              print(f"CRITICAL ERROR: Failed to credit creator {creator_id} for automation {automation_id}")
              # Consider rollback/notification
              return jsonify({'success': False, 'message': 'Purchase partially failed (seller payment). Contact support.'}), 500
    # Else: Maybe the platform owns the automation, no specific user credit needed.

    # 3. Record purchase
    purchase_data = {
        'buyer_id': buyer_id,
        'automation_id': automation_object_id,
        'creator_id': creator_id, # Store if available
        'purchase_date': datetime.datetime.utcnow(),
        'price': automation_price,
        'status': 'completed', # Or 'active_subscription' etc.
        'transaction_type': 'automation_purchase'
    }
    try:
        purchase_record = mongo.db.automation_purchases.insert_one(purchase_data) # Use a separate collection
        purchase_id = purchase_record.inserted_id
    except Exception as e:
        print(f"Error recording automation purchase {automation_id}: {e}")
        # Handle error, maybe rollback payment if possible
        return jsonify({'success': False, 'message': 'Purchase recorded partially (record failed). Contact support.'}), 500

    # Success
    updated_buyer = mongo.db.users.find_one({'_id': buyer_id}, {'balance': 1})
    new_balance = updated_buyer.get('balance', buyer['balance'] - automation_price)

    return jsonify({
        'success': True,
        'message': f'Automation "{automation["title"]}" purchased successfully for ${automation_price:.2f}.',
        'purchase_id': str(purchase_id),
        'new_balance': f'{new_balance:.2f}'
        }), 200


# --- Main Execution ---
if __name__ == '__main__':
    # Ensure Stripe key is set before starting
    if not stripe.api_key:
        print("\n" + "="*60)
        print(" WARNING: Stripe Secret Key (STRIPE_SECRET_KEY) is not set.")
        print(" Stripe functionality will be disabled.")
        print(" Please set the environment variable and restart the server.")
        print("="*60 + "\n")
    # Set host='0.0.0.0' to be accessible externally (e.g., in Docker)
    # debug=True is useful for development, but should be False in production
    app.run(host='0.0.0.0', port=5000, debug=True)
