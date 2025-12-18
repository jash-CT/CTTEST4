import os
import pytest

from app import app, init_db, db, User, Loan
from werkzeug.security import generate_password_hash


@pytest.fixture(autouse=True)
def client_env(tmp_path, monkeypatch):
    # Use a temporary DB for tests
    db_file = tmp_path / 'test_loans.db'
    monkeypatch.setenv('FLASK_SECRET_KEY', 'test-secret')
    monkeypatch.setenv('SESSION_COOKIE_SECURE', '0')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{str(db_file)}'
    init_db()
    with app.test_client() as c:
        yield c


def test_user_flow(client_env):
    c = client_env
    # register
    r = c.post('/register', json={'username': 'bob', 'password': 'pw'})
    assert r.status_code == 200
    # login
    r = c.post('/login', json={'username': 'bob', 'password': 'pw'})
    assert r.status_code == 200
    # apply loan
    r = c.post('/apply_loan', json={'amount': 2000, 'income': 3000})
    assert r.status_code == 200
    js = r.get_json()
    loan_id = js.get('loan_id')
    assert loan_id is not None
    # view loan
    r = c.get(f'/loan/{loan_id}')
    assert r.status_code == 200
    data = r.get_json()
    assert data['status'] == 'pending'


def test_admin_decision_flow(client_env):
    c = client_env
    # create admin user directly in DB
    with app.app_context():
        u = User(username='admin', password_hash=generate_password_hash('adminpw'), role='admin')
        db.session.add(u)
        db.session.commit()
        admin_id = u.id

    # create normal user and loan
    r = c.post('/register', json={'username': 'carol', 'password': 'pw'})
    assert r.status_code == 200
    r = c.post('/login', json={'username': 'carol', 'password': 'pw'})
    assert r.status_code == 200
    r = c.post('/apply_loan', json={'amount': 7000, 'income': 4000})
    loan_id = r.get_json()['loan_id']

    # login as admin by manipulating session (simplest approach)
    with c.session_transaction() as sess:
        sess['user_id'] = admin_id
        sess['role'] = 'admin'

    # approve the loan
    r = c.post(f'/admin/loan/{loan_id}/decision', json={'decision': 'approve', 'note': 'ok'})
    assert r.status_code == 200
    # check loan status
    r = c.get(f'/loan/{loan_id}')
    assert r.status_code == 200
    data = r.get_json()
    assert data['status'] == 'approved'
    assert data['decision_by'] == admin_id
