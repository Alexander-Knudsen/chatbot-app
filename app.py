import os
import json
import uuid
import requests
import urllib.parse
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, jsonify, session,
    abort, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_migrate import Migrate
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
import logging
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy import inspect

from get_db_credentials import get_db_credentials  # Ensure this import is correct

from flask_talisman import Talisman  # Import Flask-Talisman

load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)  # Preferably set via environment variable

# Configure server-side session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
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

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Retrieve the OpenAI API Key and Google Maps API Key from the environment
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY')

if not OPENAI_API_KEY:
    raise ValueError("OpenAI API key not found. Please set it as an environment variable.")
if not GOOGLE_MAPS_API_KEY:
    raise ValueError("Google Maps API key not found. Please set it as an environment variable.")

# Initialize Flask-Talisman with CSP configuration
csp = {
    'default-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
    ],
    'img-src': [
        "'self'",
        'data:',
        'https:',
    ],
    'script-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
    ],
    'style-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        "'unsafe-inline'",  # Consider removing in production
    ],
    'object-src': ["'none'"],
    'base-uri': ["'self'"]
}

Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src']
)

# Database Models

class Bot(db.Model):
    __tablename__ = 'bots'

    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(150))  # Optional image field

    # Relationships
    conversations = db.relationship('Conversation', back_populates='bot', lazy=True)

class Conversation(db.Model):
    __tablename__ = 'conversations'
    id = db.Column(db.String(128), primary_key=True)
    bot_id = db.Column(db.String(50), db.ForeignKey('bots.id'), nullable=False)
    bot = db.relationship('Bot', back_populates='conversations')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    messages = db.relationship('Message', back_populates='conversation', lazy=True)
    feedbacks = db.relationship('Feedback', back_populates='conversation', lazy=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(128), db.ForeignKey('conversations.id'), nullable=False)
    conversation = db.relationship('Conversation', back_populates='messages')
    bot_id = db.Column(db.String(50), db.ForeignKey('bots.id'), nullable=False)
    sender = db.Column(db.String(10), nullable=False)  # 'user' or 'bot'
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))  # Optional category
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(128), db.ForeignKey('conversations.id'), nullable=False)
    conversation = db.relationship('Conversation', back_populates='feedbacks')
    feedback_type = db.Column(db.String(10), nullable=False)  # 'positive' or 'negative'
    user_message = db.Column(db.Text, nullable=False)
    bot_response = db.Column(db.Text, nullable=False)
    user_feedback = db.Column(db.Text)  # Optional detailed feedback
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Simple Authentication Decorator

def login_required_custom(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Function to load bot configurations and insert into the database
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

    # Use SQLAlchemy's inspector to check if the 'bots' table exists
    inspector = inspect(db.engine)
    if inspector.has_table('bots'):
        # Insert bots into database if they don't already exist
        for bot_id, config in bot_configs.items():
            bot = Bot.query.filter_by(id=bot_id).first()
            if not bot:
                bot = Bot(
                    id=bot_id,
                    name=config.get('bot_name', 'Unnamed Bot'),
                    description=config.get('description', 'No description available.'),
                    image=config.get('image')
                )
                db.session.add(bot)
                logger.info(f"Added bot: {bot.name}")

        try:
            db.session.commit()
            logger.info("All bots have been loaded into the database.")
        except IntegrityError as e:
            db.session.rollback()
            logger.error(f"Error inserting bots into the database: {e}")
    else:
        logger.info("Bots table does not exist yet. Skipping bot insertion.")

    return bot_configs

# Load bot configurations and insert into the database within app context
with app.app_context():
    bot_configs = load_bot_configs()

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
            'model': 'gpt-4o',  # Corrected model name
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
            'model': 'gpt-4o',  # Corrected model name
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
        Message.category, func.count(Message.category)
    ).filter(
        Message.sender == 'user',
        Message.category != None
    ).group_by(
        Message.category
    ).order_by(
        func.count(Message.category).desc()
    ).all()

    # Convert results to a dictionary
    themes = {category: count for category, count in results}
    return themes

@app.route('/api/themes', methods=['GET'])
def themes():
    common_themes = get_common_themes()
    return jsonify(common_themes)

# Simple Authentication Routes

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form['username'].strip()
        password = request.form['password']

        # Get predefined credentials from environment variables
        predefined_username = os.getenv('APP_USERNAME')
        predefined_password = os.getenv('APP_PASSWORD')

        # Validate that environment variables are set
        if not predefined_username or not predefined_password:
            flash('Server configuration error. Please contact the administrator.', 'error')
            return redirect(url_for('login'))

        # Check if credentials match
        if username == predefined_username and password == predefined_password:
            # Set session as logged in
            session['logged_in'] = True
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')  # Render the login template for GET request

@app.route('/logout')
@login_required_custom
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Serve bot route with login required
@app.route('/<bot_id>', methods=['GET'])
@login_required_custom  # Ensure the user is logged in
def serve_bot(bot_id):
    config = bot_configs.get(bot_id)
    if not config:
        abort(404, description="Bot not found.")
    return render_template('chatbot.html', config=config)

# Chat API route with CSRF protection
@app.route('/api/<bot_id>/chat', methods=['POST'])
@login_required_custom  # Ensure the user is logged in
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
            bot_id=bot_id,
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
        bot_id=bot_id,
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
        bot_id=bot_id,
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
@login_required_custom  # Ensure the user is logged in
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
    logger.info(f"Feedback received: {feedback_type}")

    return jsonify({'response': 'Feedback received.'})

# Clear conversation API route
@app.route('/api/<bot_id>/clear', methods=['POST'])
@login_required_custom  # Ensure the user is logged in
@csrf.exempt     # Exempt from CSRF protection because we're using AJAX
def clear_conversation(bot_id):
    session.pop('conversation_history', None)
    session.pop('conversation_id', None)
    return jsonify({'response': 'Conversation history cleared.'})

# Directions API route
@app.route('/api/<bot_id>/directions', methods=['POST'])
@login_required_custom  # Ensure the user is logged in
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

# Dashboard Route
@app.route('/dashboard')
@login_required_custom
def dashboard():
    # Fetch all bots
    bots = Bot.query.all()

    dashboard_data = []

    for bot in bots:
        # Total interactions (Total questions asked)
        total_interactions = Message.query.filter_by(bot_id=bot.id).count()

        # Unique users (number of unique conversation IDs)
        unique_users = db.session.query(Conversation.id).filter_by(bot_id=bot.id).distinct().count()

        # Active users (today)
        today = datetime.utcnow().date()
        active_users = db.session.query(Conversation.id).filter(
            Conversation.bot_id == bot.id,
            func.date(Conversation.timestamp) == today
        ).distinct().count()

        # Average response time over time (average duration per day)
        # Step 1: Create a subquery to calculate response times
        response_times_subquery = db.session.query(
            Message.conversation_id,
            func.date(Message.timestamp).label('date'),
            (Message.timestamp - func.lag(Message.timestamp).over(
                partition_by=Message.conversation_id,
                order_by=Message.timestamp
            )).label('response_time')
        ).filter(
            Message.bot_id == bot.id,
            Message.sender == 'bot'
        ).subquery()

        # Step 2: Query the subquery to calculate the average response time per day
        avg_response_time_per_day = db.session.query(
            response_times_subquery.c.date,
            func.avg(response_times_subquery.c.response_time).label('avg_response_time')
        ).group_by(
            response_times_subquery.c.date
        ).order_by(
            response_times_subquery.c.date
        ).all()

        avg_response_dates = [artpd.date.strftime('%Y-%m-%d') for artpd in avg_response_time_per_day]
        avg_response_times = [
            artpd.avg_response_time.total_seconds() 
            for artpd in avg_response_time_per_day 
            if artpd.avg_response_time is not None
        ]

        # User satisfaction (number of thumbs up and thumbs down)
        positive_feedbacks = db.session.query(Feedback).join(Conversation).filter(
            Conversation.bot_id == bot.id,
            Feedback.feedback_type == 'positive'
        ).count()

        negative_feedbacks = db.session.query(Feedback).join(Conversation).filter(
            Conversation.bot_id == bot.id,
            Feedback.feedback_type == 'negative'
        ).count()

        total_feedbacks = positive_feedbacks + negative_feedbacks

        if total_feedbacks > 0:
            satisfaction_rate = (positive_feedbacks / total_feedbacks) * 100
        else:
            satisfaction_rate = 0

        # Top query categories
        top_categories = db.session.query(
            Message.category, func.count(Message.id).label('count')
        ).filter(
            Message.bot_id == bot.id,
            Message.sender == 'user'
        ).group_by(Message.category).order_by(func.count(Message.id).desc()).all()

        # Peak usage times (number of interactions per hour)
        peak_usage = db.session.query(
            func.extract('hour', Message.timestamp).label('hour'),
            func.count(Message.id).label('count')
        ).filter(
            Message.bot_id == bot.id
        ).group_by('hour').order_by('hour').all()

        hours = [int(pu.hour) for pu in peak_usage]
        counts = [pu.count for pu in peak_usage]

        # Chats per day (number of conversations per day)
        chats_per_day = db.session.query(
            func.date(Conversation.timestamp).label('date'),
            func.count(Conversation.id).label('count')
        ).filter(
            Conversation.bot_id == bot.id
        ).group_by('date').order_by('date').all()

        dates = [cpd.date.strftime('%Y-%m-%d') for cpd in chats_per_day]
        chat_counts = [cpd.count for cpd in chats_per_day]

        # Conversation lengths (number of messages per conversation)
        conversation_lengths = db.session.query(
            Conversation.id,
            func.count(Message.id).label('message_count')
        ).join(Message).filter(
            Conversation.bot_id == bot.id
        ).group_by(Conversation.id).all()

        lengths = [cl.message_count for cl in conversation_lengths]

        # Create bins for the histogram
        max_length = max(lengths) if lengths else 0
        bins = list(range(1, max_length + 1))
        conv_length_counts = [lengths.count(i) for i in bins]

        # Calculate Error Rate (if applicable)
        # Assuming 'error_rate' is based on messages containing the word "error"
        error_messages = Message.query.filter(
            Message.bot_id == bot.id,
            Message.sender == 'bot',
            Message.content.ilike('%error%')
        ).count()
        error_rate = (error_messages / total_interactions * 100) if total_interactions > 0 else 0

        dashboard_data.append({
            'bot': bot,
            'total_interactions': total_interactions,
            'unique_users': unique_users,
            'active_users': active_users,
            'average_response_time': round(sum(avg_response_times) / len(avg_response_times), 2) if avg_response_times else 0,
            'positive_feedbacks': positive_feedbacks,
            'negative_feedbacks': negative_feedbacks,
            'satisfaction_rate': round(satisfaction_rate, 2),
            'error_rate': round(error_rate, 2),
            'top_categories': top_categories[:5],  # Top 5 categories
            'peak_hours': hours,
            'peak_counts': counts,
            'chat_dates': dates,
            'chat_counts': chat_counts,
            'avg_response_dates': avg_response_dates,
            'avg_response_times': avg_response_times,
            'conv_length_bins': bins,
            'conv_length_counts': conv_length_counts,
        })

    return render_template('dashboard.html', dashboard_data=dashboard_data)

# Error Handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)
