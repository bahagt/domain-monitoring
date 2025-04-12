import os
import json
import logging
import logging.handlers
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import requests  # For making API calls to the backend

# Load configuration from fe_config.json
with open('fe/fe_config.json', 'r') as f:
    fe_config = json.load(f)

BACKEND_URL = os.environ.get('BACKEND_URL', "http://localhost:8080")

# Configure logging
LOG_DIRECTORY = "logs"
os.makedirs(LOG_DIRECTORY, exist_ok=True)

# Create a logger
logger = logging.getLogger('domain_monitor_fe')
logger.setLevel(logging.DEBUG)

# Create file handler
file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIRECTORY, 'domain_monitor_fe.log'),
    maxBytes=10*1024*1024,  # 10 MB
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

app = Flask(__name__)
app.secret_key = fe_config['secret_key'] # Load from config

# Example Routes (Adjust to your needs)

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        if not username or not password:
            return jsonify({"message": "Username and password are required!"}), 400

        # Make API call to the backend for login
        response = requests.post(f"{BACKEND_URL}/login", json=data)
        response_data = response.json()

        if response.status_code == 200:
            session["user"] = username
            return jsonify(response_data), 200
        else:
            return jsonify(response_data), response.status_code
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({"message": "Username and password are required!"}), 400

        # Make API call to the backend for register
        response = requests.post(f"{BACKEND_URL}/register", json=data)
        response_data = response.json()

        if response.status_code == 201:
            return jsonify(response_data), 201
        else:
            return jsonify(response_data), response.status_code
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    username = session.get("user")  # Retrieve the username from the session
    if username:  # Check if the user is logged in
        return render_template('domain.html', username=username)
    else:
        return redirect("/")  # Redirect to login page if not logged in

@app.route('/add_domain_page')
def add_domain_page():
    """Render the add domain HTML page.""" 
    username = session.get("user")  # Retrieve the username from the session
    if username:  # Check if the user is logged in
        return render_template('add_domain.html', username=username)
    else:
        return redirect("/")  # Redirect to login page if not logged in

@app.route('/domain_files')
def domain_files():
    """Render the add domain HTML page.""" 
    username = session.get("user")  # Retrieve the username from the session

    if username:  # Check if the user is logged in
            return render_template('domain_files.html', username=username)
    else:
            return redirect("/")  # Redirect to login page if not logged in

@app.route('/get_domains', methods=['GET'])
def get_domains():
    """Fetch domains from the backend."""
    try:
        username = session.get("user")
        if not username:
            return jsonify({"message": "User not logged in"}), 401
        response = requests.get(f"{BACKEND_URL}/get_domains", params={'username': username}) # Pass username as a query parameter
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with backend: {e}")
        return jsonify({"message": "Error fetching domains"}), 500

@app.route('/add_domain', methods=['POST'])
def add_domain():
    """Add a domain via the backend API."""
    try:
        username = session.get("user")
        if not username:
            return jsonify({"message": "User not logged in"}), 401
        data = request.get_json()
        response = requests.post(f"{BACKEND_URL}/add_domain", json=data, params={'username': username})  # Pass username as a query parameter
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with backend: {e}")
        return jsonify({"message": "Error adding domain"}), 500

@app.route('/remove_domain', methods=['POST'])
def remove_domain():
    """Remove a domain via the backend API."""
    try:
        username = session.get("user")
        if not username:
            return jsonify({"message": "User not logged in"}), 401
        data = request.get_json()
        response = requests.post(f"{BACKEND_URL}/remove_domain", json=data, params={'username': username})  # Pass username as a query parameter
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with backend: {e}")
        return jsonify({"message": "Error removing domain"}), 500

@app.route('/upload_domains', methods=['POST'])
def upload_domains():
    """Upload domains via the backend API."""
    try:
        username = session.get("user")
        if not username:
            return jsonify({"message": "User not logged in"}), 401

        file = request.files.get('file')

        if not file:
            return jsonify({"error": "No file provided."}), 400

        # Ensure the file is a TXT file
        if not file.filename.endswith('.txt'):
            return jsonify({"error": "Please upload a .txt file."}), 400
        
        files = {'file': (file.filename, file.stream, 'text/plain')}
        response = requests.post(f"{BACKEND_URL}/upload_domains", files=files, params={'username': username})  # Pass username as a query parameter
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with backend: {e}")
        return jsonify({"message": "Error uploading domains"}), 500

@app.route('/update_schedule', methods=['POST'])
def update_schedule():
    """Update the search frequency or schedule."""
    data = request.get_json()
    try:
        username = session.get("user")
        if not username:
            logger.warning("Attempted to update schedule without logged-in user")
            return jsonify({"message": "User not logged in"}), 401

        response = requests.post(f"{BACKEND_URL}/update_schedule", json=data, params={'username': username})  # Pass username as a query parameter
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with backend: {e}")
        return jsonify({"message": "Error updating schedule"}), 500


if __name__ == "__main__":
    app.run(debug=True, port=fe_config['port'], host='0.0.0.0')