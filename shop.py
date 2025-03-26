import asyncio
import os
from typing import Optional, List, Dict
import subprocess  # Import the subprocess module

from pywebio import start_server
from pywebio.input import *
from pywebio.output import *
from pywebio.session import *
from pywebio_battery import *

# Import the MongoDB and Stripe libraries
from pymongo import MongoClient
from pymongo.server_api import ServerApi
import stripe
import datetime


# --- Configuration ---
#  Moved to a class for better organization and testability
class Config:
    def __init__(self):
        # MongoDB Configuration
        self.mongodb_uri = "mongodb+srv://0p3nbullet:aiJ7QYL75t5pu0mo@prophetdice.8605b.mongodb.net/fiverr_clone_db?retryWrites=true&w=majority"  # Default for local development
        self.mongodb_database_name = os.environ.get("MONGODB_DATABASE", "MarketplaceDB")
        # Stripe Configuration
        self.stripe_secret_key = "sk_test_51R3gLwG1T0ctSLu4FjRjIa6WiZwhOBTsiqVDyqHq4g8ZZXCtfraHWHEI0k0dkjca2taXElootEvRU6SVBGQWCzlo00QYsiKoHh"  # IMPORTANT:  Use an environment variable
        self.stripe_publishable_key = "pk_test_51R3gLwG1T0ctSLu4x3lTiSbZKfGIe1xNMP1WojfoJpUl9ZmnYZhtCosmczG1UAXsh6YcWoTPRoLBXl4QJ6YK4ysR009oMhAQQS"  # IMPORTANT:  Use an environment variable

        # Ensure that Stripe is configured.  This will raise an exception early if the key is missing.
        if not self.stripe_secret_key.startswith("sk_"):
            raise ValueError("Invalid Stripe Secret Key.  It should start with 'sk_'")
        stripe.api_key = self.stripe_secret_key

        # Application settings
        self.host = os.environ.get("HOST", "localhost")
        self.port = int(os.environ.get("PORT", 8080))
        self.site_commission = 0.10  # 10% commission


cfg = Config()  # Instantiate the configuration


# --- MongoDB Setup ---
#  Moved to a class for better encapsulation and error handling.
class MongoDBClient:
    def __init__(self, uri, database_name):
        self.uri = uri
        self.database_name = database_name
        self.client = None
        self.db = None
        self._connect()  # Connect on instantiation

    def _connect(self):
        try:
            # Use the MongoClient with the server_api
            self.client = MongoClient(self.uri, server_api=ServerApi('1'))
            self.db = self.client[self.database_name]
            # Send a ping to confirm a successful connection
            try:
                self.client.admin.command('ping')
                print("Successfully connected to MongoDB!")
            except Exception as e:
                print(f"Error connecting to MongoDB: {e}")
                self.client = None  # Reset client on error
                self.db = None
                raise  # Re-raise the exception to be handled by caller
        except Exception as e:
            print(f"Error connecting to MongoDB: {e}")
            self.client = None  # Ensure client is None on failure
            raise  # Re-raise so the application can handle it

    def get_database(self):
        if self.db is None:
            self._connect()
        return self.db

    def close(self):
        if self.client:
            self.client.close()
            self.client = None
            self.db = None


# Global instance of the MongoDB client
mongo_client = MongoDBClient(cfg.mongodb_uri, cfg.mongodb_database_name)


# --- User Management ---
#  Refactored into a class to manage user-related database operations.
class UserManager:
    def __init__(self, db):
        self.db = db
        self.users = self.db.users  # Access collection via attribute

    def create_user(self, username, password):
        if self.users.find_one({"username": username}):
            raise ValueError("Username already exists")
        #  Password should be hashed in a real application.  This is for demonstration only.
        user_data = {"username": username, "password": password, "balance": 0, "purchases": [], "inventory": []}
        self.users.insert_one(user_data)
        return user_data

    def get_user(self, username):
        return self.users.find_one({"username": username})

    def update_user_balance(self, username, new_balance):
        self.users.update_one({"username": username}, {"$set": {"balance": new_balance}})

    def check_password(self, username, password):
        # In a real app, you'd hash the provided password and compare it to the stored hash.
        user = self.get_user(username)
        return user and user["password"] == password  # Plain text password comparison

    def add_purchase(self, username, item_id):
        self.users.update_one({"username": username}, {"$push": {"purchases": item_id}})

    def get_user_purchases(self, username):
        user = self.get_user(username)
        if user and "purchases" in user:
            return user["purchases"]
        return []

    def add_item_to_inventory(self, username, item_id):
        self.users.update_one({"username": username}, {"$push": {"inventory": item_id}})

    def get_user_inventory(self, username):
        user = self.get_user(username)
        if user and "inventory" in user:
            return user["inventory"]
        return []


# --- Item Management ---
# Refactored into a class to manage item-related database operations.
class ItemManager:
    def __init__(self, db):
        self.db = db
        self.items = self.db.items  # Access collection via attribute

    def create_item(self, name, description, price, seller_username, code=""):  # Added code parameter
        item_data = {
            "name": name,
            "description": description,
            "price": price,
            "seller_username": seller_username,
            "sold": False,
            "timestamp": datetime.datetime.utcnow(),  # Add timestamp
            "code": code,  # Store the code
        }
        result = self.items.insert_one(item_data)
        return result.inserted_id

    def get_item(self, item_id):
        return self.items.find_one({"_id": item_id})

    def get_items_for_sale(self):
        return list(self.items.find({"sold": False}).sort("timestamp", -1))  # Sort by timestamp, newest first

    def mark_item_as_sold(self, item_id):
        self.items.update_one({"_id": item_id}, {"$set": {"sold": True}})

    def get_items_by_seller(self, seller_username):
        return list(self.items.find({"seller_username": seller_username}))

    def delete_item(self, item_id):
        self.items.delete_one({"_id": item_id})



# --- Order Management ---
class OrderManager:
    def __init__(self, db):
        self.db = db
        self.orders = self.db.orders

    def create_order(self, buyer_username, seller_username, item_id, price):
        order_data = {
            "buyer_username": buyer_username,
            "seller_username": seller_username,
            "item_id": item_id,
            "price": price,
            "status": "pending",  # e.g., 'pending', 'paid', 'shipped', 'completed'
            "timestamp": datetime.datetime.utcnow()
        }
        result = self.orders.insert_one(order_data)
        return result.inserted_id

    def get_order(self, order_id):
        return self.orders.find_one({"_id": order_id})

    def update_order_status(self, order_id, status):
        self.orders.update_one({"_id": order_id}, {"$set": {"status": status}})

    def get_orders_by_buyer(self, buyer_username):
        return list(self.orders.find({"buyer_username": buyer_username}))

    def get_orders_by_seller(self, seller_username):
        return list(self.orders.find({"seller_username": seller_username}))


# --- Utility Functions ---

def format_currency(amount):
    return f"${amount:.2f}"


def display_message(title, message):
    popup(title=title, content=put_text(message))


def run_shell(script_name):
    """
    Executes a shell script and returns the output.

    Args:
        script_name (str): The name of the script to execute.

    Returns:
        str: The output of the script, or an error message if the script fails.
    """
    try:
        # Ensure the script exists and is executable
        if not os.path.exists(script_name):
            return f"Error: Script not found at {script_name}"
        if not os.access(script_name, os.X_OK):
            return f"Error: Script is not executable: {script_name}"

        # Use subprocess.run for better control and security
        process = subprocess.run(
            ["python", script_name],  # Explicitly use python for script execution
            capture_output=True,
            text=True,  # Return output as text
            check=True,  # Raise an exception for non-zero exit codes
            timeout=10,  # Add a timeout to prevent infinite loops
        )
        return process.stdout.strip()  # Return the output, removing trailing newlines

    except subprocess.CalledProcessError as e:
        return f"Error: Script failed with exit code {e.returncode}.  Output: {e.stderr.strip()}"
    except FileNotFoundError:
        return f"Error: python not found.  Please ensure python is installed and in your system's PATH."
    except TimeoutError:
        return "Error: Script execution timed out."
    except Exception as e:
        return f"An unexpected error occurred: {e}"



# --- Web Application ---
#  Refactored into a class for better organization and state management.
class MarketplaceApp:
    def __init__(self, mongo_client, stripe_client):
        self.db = mongo_client.get_database()
        self.user_manager = UserManager(self.db)
        self.item_manager = ItemManager(self.db)
        self.order_manager = OrderManager(self.db)  # Initialize OrderManager
        self.stripe_client = stripe_client
        self.current_user = None  # Track logged-in user
        self.menu_task = None  # To store the menu task

    async def main(self):
        set_env(title="Online Marketplace")
        # Start the menu as a background task
        self.menu_task = asyncio.create_task(self.show_menu())
        await self.handle_user_interaction()  # Handle other user input

    async def show_menu(self):
        while True:
            if self.current_user:
                await self.show_logged_in_menu()
            else:
                await self.show_login_menu()
            await asyncio.sleep(0.1)  # prevent the task from consuming too much CPU

    async def handle_user_interaction(self):
        while True:
            if self.current_user:
                choice = await actions(
                    f"Welcome, {self.current_user['username']}!",
                    [
                        {"label": "View Account", "value": "account"},
                        {"label": "Fund Account", "value": "fund"},
                        {"label": "List Item for Sale", "value": "list"},
                        {"label": "View Items for Sale", "value": "view_items"},
                        {"label": "View My Listings", "value": "my_listings"},
                        {"label": "View My Purchases", "value": "my_purchases"},
                        {"label": "View My Sales", "value": "my_sales"},  # Add this line
                        {"label": "Logout", "value": "logout"},
                    ],
                )
                if choice == "account":
                    await self.view_account()
                elif choice == "fund":
                    await self.fund_account()
                elif choice == "list":
                    await self.list_item()
                elif choice == "view_items":
                    await self.view_items_for_sale()
                elif choice == "my_listings":
                    await self.view_my_listings()
                elif choice == "my_purchases":
                    await self.view_my_purchases()
                elif choice == "my_sales":
                    await self.view_my_sales()  # And this line
                elif choice == "logout":
                    self.current_user = None  # Clear logged-in user
                    display_message("Logged Out", "You have been logged out.")
                    if self.menu_task:
                        self.menu_task.cancel()
                        self.menu_task = None
                    self.menu_task = asyncio.create_task(self.show_menu())

            else:
                choice = await actions(
                    "Welcome to the Online Marketplace",
                    [
                        {"label": "Login", "value": "login"},
                        {"label": "Sign Up", "value": "signup"},
                        {"label": "Exit", "value": "exit"},
                    ],
                )
                if choice == "login":
                    await self.login()
                elif choice == "signup":
                    await self.signup()
                elif choice == "exit":
                    if self.menu_task:
                        self.menu_task.cancel()
                    return  # Exit the application
            await asyncio.sleep(0.1)

    async def show_login_menu(self):
        clear()
        put_text("Welcome to the Online Marketplace")
        put_buttons(
            [
                {"label": "Login", "value": "login"},
                {"label": "Sign Up", "value": "signup"},
                {"label": "Exit", "value": "exit"},
            ],
            onclick=lambda choice: self.handle_menu_choice(choice, logged_in=False)
        )

    async def show_logged_in_menu(self):
        clear()
        username = self.current_user["username"]
        put_text(f"Welcome, {username}!")
        put_buttons(
            [
                {"label": "View Account", "value": "account"},
                {"label": "Fund Account", "value": "fund"},
                {"label": "List Item for Sale", "value": "list"},
                {"label": "View Items for Sale", "value": "view_items"},
                {"label": "View My Listings", "value": "my_listings"},
                {"label": "View My Purchases", "value": "my_purchases"},
                {"label": "View My Sales", "value": "my_sales"},
                {"label": "Logout", "value": "logout"},
            ],
            onclick=lambda choice: self.handle_menu_choice(choice, logged_in=True)
        )

    async def handle_menu_choice(self, choice, logged_in):
        if not logged_in:
            if choice == "login":
                await self.login()
            elif choice == "signup":
                await self.signup()
            elif choice == "exit":
                if self.menu_task:
                    self.menu_task.cancel()
                return  # Exit the application
        else:
            if choice == "account":
                await self.view_account()
            elif choice == "fund":
                await self.fund_account()
            elif choice == "list":
                await self.list_item()
            elif choice == "view_items":
                await self.view_items_for_sale()
            elif choice == "my_listings":
                await self.view_my_listings()
            elif choice == "my_purchases":
                await self.view_my_purchases()
            elif choice == "my_sales":
                await self.view_my_sales()
            elif choice == "logout":
                self.current_user = None
                display_message("Logged Out", "You have been logged out.")
                if self.menu_task:
                    self.menu_task.cancel()
                self.menu_task = asyncio.create_task(self.show_menu())

    async def signup(self):
        username = await input("Username", required=True)
        password = await input("Password", type=PASSWORD, required=True)
        try:
            self.user_manager.create_user(username, password)
            display_message("Success", "Account created. Please log in.")
        except ValueError as e:
            display_message("Error", str(e))

    async def login(self):
        username = await input("Username", required=True)
        password = await input("Password", type=PASSWORD, required=True)
        if self.user_manager.check_password(username, password):
            self.current_user = self.user_manager.get_user(username)
            display_message("Logged In", "Login successful.")
        else:
            display_message("Error", "Invalid credentials.")

    async def view_account(self):
        clear()
        username = self.current_user["username"]
        balance = self.current_user["balance"]
        put_text(f"Username: {username}")
        put_text(f"Balance: {format_currency(balance)}")

    async def fund_account(self):
        amount = await input("Amount to Fund", type=FLOAT, required=True)
        if amount <= 0:
            display_message("Error", "Amount must be greater than zero.")
            return

        #  Stripe integration
        try:
            # Create a Stripe charge
            charge = stripe.Charge.create(
                amount=int(amount * 100),  # Amount in cents
                currency="usd",
                source="tok_visa",  # Replace with a real token in a production environment
                description=f"Funding account for {self.current_user['username']}",
            )

            if charge.status == "succeeded":
                new_balance = self.current_user["balance"] + amount
                self.user_manager.update_user_balance(self.current_user["username"], new_balance)
                self.current_user["balance"] = new_balance  # Update the current user's balance
                display_message("Success", f"Account funded with {format_currency(amount)}.")
            else:
                display_message("Error", "Failed to fund account.  Stripe transaction failed.")

        except stripe.error.CardError as e:
            display_message("Error", f"Card error: {e.message}")
        except stripe.error.InvalidRequestError as e:
            display_message("Error", f"Invalid request: {e.message}")
        except Exception as e:
            display_message("Error", f"An error occurred: {e}")

    async def list_item(self):
        name = await input("Item Name", required=True)
        description = await input("Item Description", required=True)
        price = await input("Price", type=FLOAT, required=True)
        code = await textarea('Code', code={
            'mode': "python",
            'theme': 'darcula'
        }) # Get the code from the user
        if price <= 0:
            display_message("Error", "Price must be greater than zero.")
            return
        item_id = self.item_manager.create_item(name, description, price, self.current_user["username"], code) # Save the code
        display_message("Success", f"Item listed with ID: {item_id}.")

    async def view_items_for_sale(self):
        clear()
        items = self.item_manager.get_items_for_sale()
        if not items:
            put_text("No items currently for sale.")
            return

        # Use a list of dictionaries for the table data
        table_data = []
        for item in items:
            table_data.append({
                "Name": item["name"],
                "Description": item["description"],
                "Price": format_currency(item["price"]),
                "Seller": item["seller_username"],
                "Action": put_button(
                    "Buy",
                    onclick=lambda item_id=item["_id"], price=item["price"],
                                   seller_username=item["seller_username"]: self.purchase_item(item_id, price,
                                                                                               seller_username),
                    # Pass seller_username
                    color="primary",
                ),
            })
        put_table(table_data)

    async def purchase_item(self, item_id, price, seller_username):  # Add seller_username
        # Check if the user has enough balance
        item = self.item_manager.get_item(item_id) #get item
        if self.current_user["balance"] < price:
            display_message("Error", "Insufficient funds.")
            return

        # Calculate commission
        commission = price * cfg.site_commission
        seller_proceeds = price - commission

        #  Create Order
        order_id = self.order_manager.create_order(self.current_user["username"], seller_username, item_id, price)

        # Update user balances and item status
        new_balance = self.current_user["balance"] - price
        self.user_manager.update_user_balance(self.current_user["username"], new_balance)
        self.current_user["balance"] = new_balance  # Update current user's balance
        self.item_manager.mark_item_as_sold(item_id)
        self.user_manager.add_purchase(self.current_user["username"], item_id)
        self.user_manager.add_item_to_inventory(self.current_user["username"], item_id)  # add item to inventory

        #  Update Seller's Balance.
        seller = self.user_manager.get_user(seller_username)  # Get Seller's User Data
        if seller:
            new_seller_balance = seller["balance"] + seller_proceeds
            self.user_manager.update_user_balance(seller_username, new_seller_balance)

        display_message("Success", "Item purchased.")

    async def view_my_listings(self):
        clear()
        items = self.item_manager.get_items_by_seller(self.current_user["username"])
        if not items:
            put_text("You have no listings.")
            return
        # Use a list of dictionaries for the table
        table_data = []
        for item in items:
            table_data.append({
                "Name": item["name"],
                "Description": item["description"],
                "Price": format_currency(item["price"]),
                "Sold": "Yes" if item["sold"] else "No",
                "Action": put_button(
                    "Delete",
                    onclick=lambda item_id=item["_id"]: self.delete_listing(item_id),
                    color="danger"
                )
            })
        put_table(table_data)

    async def delete_listing(self, item_id):
        item = self.item_manager.get_item(item_id)
        if not item:
            display_message("Error", "Item not found.")
            return

        if item["seller_username"] != self.current_user["username"]:
            display_message("Error", "You are not the seller of this item.")
            return

        self.item_manager.delete_item(item_id)
        display_message("Success", "Item deleted.")
        await self.view_my_listings()  # Refresh the list

    async def view_my_purchases(self):
        clear()
        purchases = self.user_manager.get_user_purchases(self.current_user["username"])
        if not purchases:
            put_text("You have not made any purchases.")
            return

        #  Get item details for display
        items = []
        for item_id in purchases:
            item = self.item_manager.get_item(item_id)  # Assuming you have a get_item method
            if item:
                items.append(item)

        if not items:
            put_text("No items found for your purchases.")
            return

        # Use a list of dictionaries for the table
        table_data = []
        for item in items:
            table_data.append({
                "Name": item["name"],
                "Description": item["description"],
                "Price": format_currency(item["price"]),
                "Seller": item["seller_username"],
                "Action": put_button(  # Add a "Use" button
                    label="Use",
                    onclick=lambda item_id=item["_id"]: self.use_item(item_id), # Pass item id
                    color="success",
                )
            })
        put_table(table_data)

    async def use_item(self, item_id):
        """
        Executes the code associated with the item and displays the output.

        Args:
            item_id: The ID of the item being used.
        """
        # For security, you should validate the item_id against the user's inventory
        # to ensure they actually own the item before attempting to use it.
        user_inventory = self.user_manager.get_user_inventory(self.current_user["username"])
        if item_id not in user_inventory:
            display_message("Error", "You do not own this item.")
            return

        # Get the item from the database
        item = self.item_manager.get_item(item_id)
        if not item:
            display_message("Error", "Item not found.")
            return

        code = item["code"] # get code from item

        # Write the code to a file
        with open("test.py", "w") as f:
            f.write(code)
        os.chmod("test.py", 0o755)  # Make the script executable

        output = run_shell("test.py")  # Execute the script
        popup("Script Output", put_text(output))  # Display the output in a popup

    async def view_my_sales(self):
        clear()
        items = self.item_manager.get_items_by_seller(self.current_user["username"])
        sold_items = [item for item in items if item["sold"]]
        if not sold_items:
            put_text("You have not sold any items.")
            return

        # Use a list of dictionaries for the table.
        table_data = []
        for item in sold_items:
            table_data.append({
                "Name": item["name"],
                "Description": item["description"],
                "Price": format_currency(item["price"]),
            })
        put_table(table_data)


def start_app():
    app = MarketplaceApp(mongo_client, stripe)
    start_server(app.main, port=cfg.port, debug=True)


if __name__ == "__main__":
    start_app()
