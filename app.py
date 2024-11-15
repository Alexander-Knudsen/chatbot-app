import os
import json
import uuid
import requests
import urllib.parse
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, abort, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
import logging
from werkzeug.security import generate_password_hash, check_password_hash

from get_db_credentials import get_db_credentials  # Ensure this import is correct

load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)  # Preferably set via environment variable

# Configure server-side session
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on the server filesystem
app.config['SESSION_FILE_DIR'] = './flask_session'  # Path where session files will be stored
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Configure secure cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,       # Ensures cookies are sent over HTTPS
    SESSION_COOKIE_HTTPONLY=True,     # Prevents JavaScript access to cookies
    SESSION_COOKIE_SAMESITE='Lax'     # Mitigates CSRF
)

# Initialize Flask-Session
Session(app)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Retrieve database credentials using get_db_credentials
db_credentials = get_db_credentials()

# Configure SQLAlchemy with the retrieved credentials
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"postgresql://{db_credentials['username']}:{db_credentials['password']}"
    f"@{db_credentials['host']}:{db_credentials.get('port', 5432)}/{db_credentials['dbname']}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Token Serializer
serializer = URLSafeTimedSerializer(app.secret_key)

# Retrieve the OpenAI API Key and Google Maps API Key from the environment
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY')

if not OPENAI_API_KEY:
    raise ValueError("OpenAI API key not found. Please set it as an environment variable.")
if not GOOGLE_MAPS_API_KEY:
    raise ValueError("Google Maps API key not found. Please set it as an environment variable.")

# Load all bot configurations
def load_bot_configs():
    config_dir = os.path.join(os.path.dirname(__file__), 'config')
    bot_configs = {}
    for filename in os.listdir(config_dir):
        if filename.endswith('.json'):
            with open(os.path.join(config_dir, filename), 'r', encoding='utf-8') as f:
                config = json.load(f)
                bot_id = config.get('bot_id')
                if bot_id:
                    bot_configs[bot_id] = config
                else:
                    logger.warning(f"Bot configuration in {filename} missing 'bot_id'.")
    return bot_configs

bot_configs = load_bot_configs()

# Database Models

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)  # Keep as Integer for auto-increment
    email = db.Column(db.String(150), unique=True, nullable=False)  # New Email Field
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)  # Changed to db.Text

    # Relationships
    conversations = db.relationship('Conversation', backref='user', lazy=True)
    embed_tokens = db.relationship('EmbedToken', backref='user', lazy=True)
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class EmbedToken(db.Model):
    __tablename__ = 'embed_tokens'
    id = db.Column(db.String(128), primary_key=True)
    token = db.Column(db.String(256), unique=True, nullable=False)
    bot_id = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Integer to match User.id
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)

class Conversation(db.Model):
    __tablename__ = 'conversations'
    id = db.Column(db.String(128), primary_key=True)  # UUIDs for conversation IDs
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Integer to match User.id
    bot_id = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    messages = db.relationship('Message', backref='conversation', lazy=True)
    feedbacks = db.relationship('Feedback', backref='conversation', lazy=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(128), db.ForeignKey('conversations.id'), nullable=False)
    sender = db.Column(db.String(10), nullable=False)  # 'user' or 'bot'
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))  # Optional category
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Integer to match User.id
    conversation_id = db.Column(db.String(128), db.ForeignKey('conversations.id'), nullable=False)
    feedback_type = db.Column(db.String(10), nullable=False)  # 'positive' or 'negative'
    user_message = db.Column(db.Text, nullable=False)
    bot_response = db.Column(db.Text, nullable=False)
    user_feedback = db.Column(db.Text)  # Optional detailed feedback
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Function to create the system message with specific instructions and bot data
def create_system_message(bot_config):
    # Load bot-specific data files
    bot_data = {}
    for data_file in bot_config.get('json_files', []):
        file_path = os.path.join(os.path.dirname(__file__), 'data', data_file)
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Use the filename (without extension) as the key
                key = os.path.splitext(data_file)[0]
                bot_data[key] = data

    # Create the system message content
    system_content = (
        f"You are {bot_config['bot_name']}, a helpful and polite assistant. "
        f"{bot_config.get('prompt_additional', '')} "
        "You have access to the following information:\n"
        f"{json.dumps(bot_data, indent=2)}\n"
        "Your role is to answer questions based on this information. "
        "Always be polite and concise in your responses. "
        "Remember previous interactions and respond to follow-up questions accordingly. "
        "You are fluent in all languages and should respond in the language the user uses. "
        "If something is unclear, politely ask the user for clarification. "
        "Keep answers short and to the point, and format them as nicely as possible using markdown. "
        "When the user requests directions, you can use Google Maps to generate a directions link."
    )

    return {
        "role": "system",
        "content": system_content
    }

def query_chatgpt(messages, max_tokens=700, temperature=0.5):
    # Properly format the messages to send to the API
    formatted_messages = [{"role": message["role"], "content": message["content"]} for message in messages]

    # Send the conversation history to the OpenAI API
    response = requests.post(
        'https://api.openai.com/v1/chat/completions',
        headers={
            'Authorization': f'Bearer {OPENAI_API_KEY}',
            'Content-Type': 'application/json'
        },
        json={
            'model': 'gpt-4',  # Update model as needed
            'messages': formatted_messages,
            'max_tokens': max_tokens,
            'temperature': temperature
        }
    )

    if response.status_code != 200:
        logger.error(f"Error from OpenAI API: {response.status_code}, {response.text}")
        return None, response.status_code

    response_json = response.json()
    return response_json['choices'][0]['message']['content'], None

def categorize_message(user_message):
    # Define your categories
    categories = ["booking", "housing", "amenities", "directions", "pricing", "other"]

    # Create the prompt for categorization
    categorization_prompt = (
        f"Please categorize the following user message into one of the following categories: {', '.join(categories)}.\n\n"
        f"User message: \"{user_message}\"\n\n"
        "Category:"
    )

    # Make the GPT call
    response = requests.post(
        'https://api.openai.com/v1/chat/completions',
        headers={
            'Authorization': f'Bearer {OPENAI_API_KEY}',
            'Content-Type': 'application/json'
        },
        json={
            'model': 'gpt-4',  # Update model as needed
            'messages': [
                {'role': 'system', 'content': 'You are a helpful assistant that categorizes user messages.'},
                {'role': 'user', 'content': categorization_prompt}
            ],
            'max_tokens': 10,
            'temperature': 0
        }
    )

    if response.status_code != 200:
        logger.error(f"Error from OpenAI API: {response.status_code}, {response.text}")
        return 'other'  # Default category

    response_json = response.json()
    category = response_json['choices'][0]['message']['content'].strip().lower()

    # Ensure the category is valid
    if category not in categories:
        category = 'other'

    return category

def get_common_themes():
    # Query messages and count categories
    results = db.session.query(
        Message.category, db.func.count(Message.category)
    ).filter(
        Message.sender == 'user',
        Message.category != None
    ).group_by(
        Message.category
    ).order_by(
        db.func.count(Message.category).desc()
    ).all()

    # Convert results to a dictionary
    themes = {category: count for category, count in results}
    return themes

@app.route('/api/themes', methods=['GET'])
def themes():
    common_themes = get_common_themes()
    return jsonify(common_themes)

# Home route to display all bots
@app.route('/')
def home():
    bots = []
    for bot_id, config in bot_configs.items():
        bots.append({
            'id': bot_id,
            'name': config.get('bot_name', 'Unnamed Bot'),
            'description': config.get('description', 'No description available.'),
            'url': f"/{bot_id}",
            'image': config.get('image')  # Optional: Include if you have images
        })
    return render_template('index.html', bots=bots)

# Serve bot route with login required
@app.route('/<bot_id>', methods=['GET'])
@login_required  # Ensure the user is logged in
def serve_bot(bot_id):
    config = bot_configs.get(bot_id)
    if not config:
        abort(404, description="Bot not found.")
    # Optionally, check if the user has access to this bot
    # For now, assuming all logged-in users have access to all bots
    return render_template('chatbot.html', config=config)

# Chat API route with CSRF protection
@app.route('/api/<bot_id>/chat', methods=['POST'])
@login_required  # Ensure the user is logged in
@csrf.exempt     # Exempt from CSRF protection because we're using AJAX
def chat(bot_id):
    config = bot_configs.get(bot_id)
    if not config:
        return jsonify({'error': 'Bot configuration not found.'}), 404

    data = request.get_json()
    user_message = data.get('message', '').strip()

    # Generate or retrieve conversation ID
    conversation_id = session.get('conversation_id')
    if not conversation_id:
        conversation = Conversation(
            id=str(uuid.uuid4()),
            user_id=current_user.id,
            bot_id=bot_id
        )
        db.session.add(conversation)
        db.session.commit()
        conversation_id = conversation.id
        session['conversation_id'] = conversation_id
    else:
        conversation = Conversation.query.get(conversation_id)
        if not conversation:
            # If conversation not found in DB, create a new one
            conversation = Conversation(
                id=str(uuid.uuid4()),
                user_id=current_user.id,
                bot_id=bot_id
            )
            db.session.add(conversation)
            db.session.commit()
            conversation_id = conversation.id
            session['conversation_id'] = conversation_id

    # Ensure conversation history exists in the session
    if 'conversation_history' not in session:
        session['conversation_history'] = []
        session['conversation_history'].append(create_system_message(config))

    # Handle the 'greet' command
    if user_message.lower() == 'greet':
        greeting_message = config.get('prompt', 'Hello! How can I assist you today?')
        session['conversation_history'].append({"role": "assistant", "content": greeting_message})

        # Save bot's response to the database
        bot_message_entry = Message(
            conversation_id=conversation_id,
            sender='bot',
            content=greeting_message
        )
        db.session.add(bot_message_entry)
        db.session.commit()

        return jsonify({'response': greeting_message})

    # Append the user's message to the conversation history
    session['conversation_history'].append({"role": "user", "content": user_message})

    # Categorize the user's message
    category = categorize_message(user_message)

    # Save user's message to the database
    user_message_entry = Message(
        conversation_id=conversation_id,
        sender='user',
        content=user_message,
        category=category
    )
    db.session.add(user_message_entry)
    db.session.commit()  # Commit to generate message ID

    # Send the conversation history to ChatGPT
    response_message, error = query_chatgpt(session['conversation_history'])
    if error:
        return jsonify({'error': 'Error communicating with ChatGPT'}), error

    # Append the assistant's response to the conversation history
    session['conversation_history'].append({"role": "assistant", "content": response_message})

    # Save assistant's response to the database
    bot_message_entry = Message(
        conversation_id=conversation_id,
        sender='bot',
        content=response_message
    )
    db.session.add(bot_message_entry)
    db.session.commit()

    # Mark session as modified to ensure it gets saved
    session.modified = True

    return jsonify({'response': response_message})

# Feedback API route
@app.route('/api/<bot_id>/feedback', methods=['POST'])
@login_required  # Ensure the user is logged in
@csrf.exempt     # Exempt from CSRF protection because we're using AJAX
def feedback(bot_id):
    data = request.get_json()
    feedback_type = data.get('feedback')       # 'positive' or 'negative'
    user_message = data.get('user_message')    # The latest user message
    bot_response = data.get('bot_response')    # The bot's response
    user_feedback = data.get('user_feedback', '')  # Optional detailed feedback

    conversation_id = session.get('conversation_id')

    if not conversation_id:
        return jsonify({'error': 'No active conversation found.'}), 400

    # Create a new Feedback object
    feedback_entry = Feedback(
        user_id=current_user.id,
        conversation_id=conversation_id,
        feedback_type=feedback_type,
        user_message=user_message,
        bot_response=bot_response,
        user_feedback=user_feedback
    )

    try:
        db.session.add(feedback_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving feedback: {e}")
        return jsonify({'error': 'An error occurred while saving feedback.'}), 500

    # Log the feedback to the console (optional)
    logger.info(f"Feedback received from user {current_user.id}: {feedback_type}")

    return jsonify({'response': 'Feedback received.'})

# Clear conversation API route
@app.route('/api/<bot_id>/clear', methods=['POST'])
@login_required  # Ensure the user is logged in
@csrf.exempt     # Exempt from CSRF protection because we're using AJAX
def clear_conversation(bot_id):
    session.pop('conversation_history', None)
    session.pop('conversation_id', None)
    return jsonify({'response': 'Conversation history cleared.'})

# Directions API route
@app.route('/api/<bot_id>/directions', methods=['POST'])
@login_required  # Ensure the user is logged in
@csrf.exempt     # Exempt from CSRF protection because we're using AJAX
def directions(bot_id):
    data = request.get_json()
    user_location = data.get('user_location', '').strip()

    # If user location is not provided, ask for it
    if not user_location:
        return jsonify({
            "response": "Could you please provide your starting location to get directions?"
        })

    # Get the destination from the bot's configuration or default
    config = bot_configs.get(bot_id)
    destination = config.get('destination')

    if not destination:
        logger.error(f"Destination not configured for bot {bot_id}")
        return jsonify({
            "response": "Destination not configured for this bot."
        }), 500

    directions_url = (
        f"https://www.google.com/maps/dir/?api=1&origin={urllib.parse.quote(user_location)}"
        f"&destination={urllib.parse.quote(destination)}&travelmode=driving"
    )

    response = {
        "response": f"Here is your [Google Maps link for directions]({directions_url})."
    }

    return jsonify(response)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Basic validation
        if not email or not username or not password or not confirm_password:
            flash('Please fill out all fields.', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(
            email=email,
            username=username
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Registration successful!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        email = request.form['email'].strip().lower()
        password = request.form['password']

        # Query the user from the database using email
        user = User.query.filter_by(email=email).first()

        # Check if user exists and password is correct
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))  # Redirect back to login page with error message
    else:
        return render_template('login.html')  # Render the login template for GET request

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Embed Code Generation Route
@app.route('/generate_embed', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def generate_embed():
    data = request.get_json()
    bot_id = data.get('bot_id')
    if not bot_id or bot_id not in bot_configs:
        return jsonify({'error': 'Invalid bot ID'}), 400

    token = generate_embed_token(bot_id, current_user.id)
    embed_url = f"{request.url_root}embed/{bot_id}?token={token}"
    embed_code = f'<iframe src="{embed_url}" width="350" height="500" frameborder="0" sandbox="allow-scripts allow-same-origin"></iframe>'

    return jsonify({'embed_code': embed_code})

# Token Generation Function
def generate_embed_token(bot_id, user_id, expiration=86400):
    data = {'bot_id': bot_id, 'user_id': user_id}
    token = serializer.dumps(data)
    expires_at = datetime.utcnow() + timedelta(seconds=expiration)

    embed_token = EmbedToken(
        id=str(uuid.uuid4()),
        token=token,
        bot_id=bot_id,
        user_id=user_id,
        expires_at=expires_at
    )
    db.session.add(embed_token)
    db.session.commit()

    return token

# Token Validation Decorator
def token_required(f):
    @wraps(f)
    def decorated_function(bot_id, *args, **kwargs):
        token = request.args.get('token')
        if not token:
            abort(403, description="Token is missing.")

        try:
            data = serializer.loads(token, max_age=86400)  # Token expires in 1 day
            if data['bot_id'] != bot_id:
                abort(403, description="Invalid token for this bot.")
        except SignatureExpired:
            abort(403, description="Token has expired.")
        except BadSignature:
            abort(403, description="Invalid token.")

        return f(bot_id, *args, **kwargs)
    return decorated_function

# Embed route with token validation
@app.route('/embed/<bot_id>', methods=['GET'])
@token_required
def embed_bot(bot_id):
    config = bot_configs.get(bot_id)
    if not config:
        abort(404, description="Bot not found.")
    return render_template('chatbot.html', config=config)

# After Request to set CSP Headers
@app.after_request
def set_csp_headers(response):
    response.headers['Content-Security-Policy'] = "script-src 'self' https://cdn.jsdelivr.net; object-src 'none'; base-uri 'self';"
    return response

if __name__ == '__main__':
    app.run(debug=True)
