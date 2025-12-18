import os
from datetime import datetime
from functools import wraps

from flask import Flask, request, session, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'loans.db')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key')
# Session cookie hardening (can be overridden by env in development)
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Set SESSION_COOKIE_SECURE if running under HTTPS in production
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '0') == '1'
# Optional SameSite setting (Lax by default)
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
# Session lifetime (seconds) - optional
try:
    sess_t = int(os.environ.get('SESSION_LIFETIME_SECONDS', '3600'))
except Exception:
    sess_t = 3600
app.config['PERMANENT_SESSION_LIFETIME'] = sess_t

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    income = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    decision_by = db.Column(db.Integer, nullable=True)
    decision_at = db.Column(db.DateTime, nullable=True)
    decision_note = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', backref='loans')


def init_db(create_admin_from_env=True):
    """Create database tables. Optionally create admin from env vars ADMIN_USER and ADMIN_PASS or via ADMIN_TOKEN mechanism."""
    # Ensure we create tables within the Flask application context
    with app.app_context():
        db.create_all()
        # Optionally create an admin user if env vars set and admin doesn't exist
        admin_user = os.environ.get('ADMIN_USER')
        admin_pass = os.environ.get('ADMIN_PASS')
        if create_admin_from_env and admin_user and admin_pass:
            existing = User.query.filter_by(username=admin_user).first()
            if not existing:
                u = User(username=admin_user, password_hash=generate_password_hash(admin_pass), role='admin')
                db.session.add(u)
                db.session.commit()
                print(f'Created admin user: {admin_user}')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'authentication required'}), 401
        g.user = User.query.get(session['user_id'])
        if g.user is None:
            session.clear()
            return jsonify({'error': 'invalid session'}), 401
        return f(*args, **kwargs)

    return decorated


def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'authentication required'}), 401
            user = User.query.get(session['user_id'])
            if not user or user.role != role:
                return jsonify({'error': 'forbidden'}), 403
            g.user = user
            return f(*args, **kwargs)

        return decorated

    return decorator


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'username already exists'}), 400
    user = User(username=username, password_hash=generate_password_hash(password), role='user')
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'user registered'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'invalid credentials'}), 401
    session.clear()
    session['user_id'] = user.id
    session['role'] = user.role
    return jsonify({'message': 'logged in', 'role': user.role})


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'logged out'})


@app.route('/apply_loan', methods=['POST'])
@login_required
def apply_loan():
    data = request.get_json() or {}
    try:
        amount = float(data.get('amount', 0))
        income = float(data.get('income', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'amount and income must be numbers'}), 400
    if amount <= 0 or income <= 0:
        return jsonify({'error': 'amount and income must be greater than 0'}), 400
    loan = Loan(user_id=session['user_id'], amount=amount, income=income, status='pending')
    db.session.add(loan)
    db.session.commit()
    return jsonify({'message': 'loan applied', 'loan_id': loan.id})


@app.route('/loans', methods=['GET'])
@login_required
def list_loans():
    user = g.user
    if user.role == 'admin':
        loans = Loan.query.order_by(Loan.applied_at.desc()).all()
    else:
        loans = Loan.query.filter_by(user_id=user.id).order_by(Loan.applied_at.desc()).all()
    out = []
    for L in loans:
        out.append({
            'id': L.id,
            'user_id': L.user_id,
            'amount': L.amount,
            'income': L.income,
            'status': L.status,
            'applied_at': L.applied_at.isoformat(),
            'decision_by': L.decision_by,
            'decision_at': L.decision_at.isoformat() if L.decision_at else None,
            'decision_note': L.decision_note,
        })
    return jsonify({'loans': out})


@app.route('/loan/<int:loan_id>', methods=['GET'])
@login_required
def view_loan(loan_id):
    loan = Loan.query.get(loan_id)
    if not loan:
        return jsonify({'error': 'loan not found'}), 404
    if g.user.role != 'admin' and loan.user_id != g.user.id:
        return jsonify({'error': 'forbidden'}), 403
    return jsonify({
        'id': loan.id,
        'user_id': loan.user_id,
        'amount': loan.amount,
        'income': loan.income,
        'status': loan.status,
        'applied_at': loan.applied_at.isoformat(),
        'decision_by': loan.decision_by,
        'decision_at': loan.decision_at.isoformat() if loan.decision_at else None,
        'decision_note': loan.decision_note,
    })


@app.route('/admin/loan/<int:loan_id>/decision', methods=['POST'])
@role_required('admin')
def decide_loan(loan_id):
    loan = Loan.query.get(loan_id)
    if not loan:
        return jsonify({'error': 'loan not found'}), 404
    data = request.get_json() or {}
    decision = (data.get('decision') or '').lower()
    note = data.get('note')
    if decision not in ('approve', 'reject'):
        return jsonify({'error': "decision must be 'approve' or 'reject'"}), 400
    loan.status = 'approved' if decision == 'approve' else 'rejected'
    loan.decision_by = g.user.id
    loan.decision_at = datetime.utcnow()
    loan.decision_note = note
    db.session.commit()
    return jsonify({'message': f'loan {loan.status}'})


@app.route('/init_admin', methods=['POST'])
def init_admin():
    """Create an admin user using a simple ADMIN_TOKEN header to prevent casual creation.
    Provide header 'X-ADMIN-TOKEN' equal to environment ADMIN_TOKEN, and JSON {username, password}.
    """
    token = request.headers.get('X-ADMIN-TOKEN')
    expected = os.environ.get('ADMIN_TOKEN')
    if not expected or token != expected:
        return jsonify({'error': 'invalid admin token'}), 403
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'username exists'}), 400
    user = User(username=username, password_hash=generate_password_hash(password), role='admin')
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'admin created'})


if __name__ == '__main__':
    # Ensure DB exists and optionally create admin from env
    init_db(create_admin_from_env=True)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
