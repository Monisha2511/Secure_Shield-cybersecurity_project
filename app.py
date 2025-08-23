from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime
import json
import re

app = Flask(__name__, template_folder='frontend')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersecurity.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
CORS(app)

# Database Models
class PasswordCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    strength = db.Column(db.Integer, nullable=False)
    length = db.Column(db.Integer, nullable=False)
    has_upper = db.Column(db.Boolean, nullable=False)
    has_lower = db.Column(db.Boolean, nullable=False)
    has_number = db.Column(db.Boolean, nullable=False)
    has_special = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class PhishingCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Float, nullable=False)
    indicators = db.Column(db.String, nullable=False)
    content_length = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class TwoFAInterest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ThreatRefresh(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class NewsletterSubscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    subscribed = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LearningProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100))  # Could be email or session ID
    course_name = db.Column(db.String(100), nullable=False)
    progress = db.Column(db.Integer, default=0)  # 0-100%
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ModuleCompletion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100))
    course_name = db.Column(db.String(100), nullable=False)
    module_index = db.Column(db.Integer, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# API Routes
@app.route('/api/password_check', methods=['POST'])
def log_password_check():
    data = request.json
    new_check = PasswordCheck(
        strength=data['strength'],
        length=data['length'],
        has_upper=data['has_upper'],
        has_lower=data['has_lower'],
        has_number=data['has_number'],
        has_special=data['has_special']
    )
    db.session.add(new_check)
    db.session.commit()
    return jsonify({'message': 'Password check logged successfully'})

@app.route('/api/phishing_check', methods=['POST'])
def log_phishing_check():
    data = request.json
    new_check = PhishingCheck(
        score=data['score'],
        indicators=json.dumps(data['indicators']),
        content_length=data['content_length']
    )
    db.session.add(new_check)
    db.session.commit()
    return jsonify({'message': 'Phishing check logged successfully'})

@app.route('/api/2fa_interest', methods=['POST'])
def log_2fa_interest():
    data = request.json
    new_interest = TwoFAInterest(service=data['service'])
    db.session.add(new_interest)
    db.session.commit()
    return jsonify({'message': '2FA interest logged successfully'})

@app.route('/api/threat_refresh', methods=['POST'])
def log_threat_refresh():
    new_refresh = ThreatRefresh()
    db.session.add(new_refresh)
    db.session.commit()
    return jsonify({'message': 'Threat refresh logged successfully'})

@app.route('/api/newsletter/subscribe', methods=['POST'])
def subscribe_newsletter():
    data = request.json
    email = data.get('email', '').strip().lower()
    
    # Validate email
    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'error': 'Invalid email address'}), 400
    
    # Check if already subscribed
    existing = NewsletterSubscriber.query.filter_by(email=email).first()
    if existing:
        if existing.subscribed:
            return jsonify({'message': 'Email already subscribed'}), 200
        else:
            existing.subscribed = True
            existing.timestamp = datetime.utcnow()
            db.session.commit()
            return jsonify({'message': 'Resubscribed successfully'})
    
    # Add new subscriber
    new_subscriber = NewsletterSubscriber(email=email)
    db.session.add(new_subscriber)
    db.session.commit()
    
    return jsonify({'message': 'Subscribed successfully'})

@app.route('/api/learning/start', methods=['POST'])
def start_learning():
    data = request.json
    course_name = data.get('course_name', '')
    user_id = data.get('user_id', 'anonymous')
    
    if not course_name:
        return jsonify({'error': 'Course name is required'}), 400
    
    # Check if already started this course
    progress = LearningProgress.query.filter_by(
        user_id=user_id, 
        course_name=course_name
    ).first()
    
    if progress:
        return jsonify({
            'message': 'Course already started', 
            'progress': progress.progress,
            'redirect_url': f'/learning/{course_name.lower().replace(" ", "-")}'
        })
    
    # Create new learning progress
    new_progress = LearningProgress(
        user_id=user_id,
        course_name=course_name,
        progress=0
    )
    db.session.add(new_progress)
    db.session.commit()
    
    return jsonify({
        'message': 'Learning started successfully',
        'redirect_url': f'/learning/{course_name.lower().replace(" ", "-")}'
    })

@app.route('/api/learning/progress', methods=['POST'])
def update_learning_progress():
    data = request.json
    course_name = data.get('course_name')
    module_index = data.get('module_index')
    user_id = data.get('user_id', 'anonymous')
    
    if not course_name or module_index is None:
        return jsonify({'error': 'Course name and module index are required'}), 400
    
    # Record module completion
    completion = ModuleCompletion.query.filter_by(
        user_id=user_id,
        course_name=course_name,
        module_index=module_index
    ).first()
    
    if not completion:
        completion = ModuleCompletion(
            user_id=user_id,
            course_name=course_name,
            module_index=module_index,
            completed=True
        )
        db.session.add(completion)
    else:
        completion.completed = True
        completion.timestamp = datetime.utcnow()
    
    # Calculate overall progress
    total_modules = 4
    completed_modules = ModuleCompletion.query.filter_by(
        user_id=user_id,
        course_name=course_name,
        completed=True
    ).count()
    
    progress_percentage = min(100, int((completed_modules / total_modules) * 100))
    
    # Update or create learning progress record
    progress = LearningProgress.query.filter_by(
        user_id=user_id, 
        course_name=course_name
    ).first()
    
    if progress:
        progress.progress = progress_percentage
        progress.timestamp = datetime.utcnow()
    else:
        progress = LearningProgress(
            user_id=user_id,
            course_name=course_name,
            progress=progress_percentage
        )
        db.session.add(progress)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Progress updated successfully',
        'progress': progress_percentage
    })

@app.route('/api/learning/progress', methods=['GET'])
def get_learning_progress():
    user_id = request.args.get('user_id', 'anonymous')
    course_name = request.args.get('course_name')
    
    if not course_name:
        return jsonify({'error': 'Course name is required'}), 400
    
    progress = LearningProgress.query.filter_by(
        user_id=user_id, 
        course_name=course_name
    ).first()
    
    if progress:
        return jsonify({
            'progress': progress.progress,
            'last_updated': progress.timestamp.isoformat()
        })
    else:
        return jsonify({
            'progress': 0,
            'message': 'No progress record found'
        })

@app.route('/api/analytics/password_strength', methods=['GET'])
def get_password_analytics():
    weak = PasswordCheck.query.filter(PasswordCheck.strength < 40).count()
    medium = PasswordCheck.query.filter(PasswordCheck.strength >= 40, PasswordCheck.strength < 80).count()
    strong = PasswordCheck.query.filter(PasswordCheck.strength >= 80).count()
    
    return jsonify({
        'weak': weak,
        'medium': medium,
        'strong': strong
    })

@app.route('/api/analytics/threat_distribution', methods=['GET'])
def get_threat_analytics():
    return jsonify({
        'phishing': 40,
        'malware': 25,
        'weak_password': 20,
        'social_engineering': 15
    })

@app.route('/api/check_history', methods=['GET'])
def get_check_history():
    password_checks = PasswordCheck.query.order_by(PasswordCheck.timestamp.desc()).limit(5).all()
    phishing_checks = PhishingCheck.query.order_by(PhishingCheck.timestamp.desc()).limit(5).all()
    
    history = []
    
    for check in password_checks:
        if check.strength < 40:
            result = 'Weak'
        elif check.strength < 80:
            result = 'Medium'
        else:
            result = 'Strong'
            
        history.append({
            'date': check.timestamp.strftime('%m/%d/%Y %H:%M'),
            'tool': 'Password Check',
            'result': result
        })
    
    for check in phishing_checks:
        if check.score < 0.3:
            result = 'Legitimate'
        elif check.score < 0.7:
            result = 'Suspicious'
        else:
            result = 'Phishing'
            
        history.append({
            'date': check.timestamp.strftime('%m/%d/%Y %H:%M'),
            'tool': 'Phishing Detection',
            'result': result
        })
    
    history.sort(key=lambda x: datetime.strptime(x['date'], '%m/%d/%Y %H:%M'), reverse=True)
    return jsonify(history[:5])

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    # Get analytics data for the dashboard
    password_analytics = get_password_analytics().json
    threat_analytics = get_threat_analytics().json
    check_history = get_check_history().json
    
    # Get learning progress data
    learning_progress = {}
    courses = ['Cybersecurity Basics', 'Phishing Awareness', 'Password Management']
    for course in courses:
        progress = LearningProgress.query.filter_by(
            user_id='anonymous',  # In a real app, you'd use the actual user ID
            course_name=course
        ).first()
        learning_progress[course] = progress.progress if progress else 0
    
    return render_template('dashboard.html', 
                         password_analytics=password_analytics,
                         threat_analytics=threat_analytics,
                         check_history=check_history,
                         learning_progress=learning_progress)

# Learning Pages
@app.route('/learning/<course>')
def learning_page(course):
    # Map URL-friendly course names to display names
    course_map = {
        'cybersecurity-basics': 'Cybersecurity Basics',
        'phishing-awareness': 'Phishing Awareness',
        'password-management': 'Password Management'
    }
    
    course_name = course_map.get(course, course.replace('-', ' ').title())
    return render_template('learning.html', course_name=course_name)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)