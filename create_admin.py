import os
import sys
from getpass import getpass

from app import init_db, db, User
from werkzeug.security import generate_password_hash


def create_admin(username: str, password: str):
    with __import__('app').app.app_context():
        init_db()
        if User.query.filter_by(username=username).first():
            print(f'User {username} already exists')
            return
        u = User(username=username, password_hash=generate_password_hash(password), role='admin')
        db.session.add(u)
        db.session.commit()
        print(f'Admin user {username} created')


def main():
    # Accept username/password from env or args or prompt
    username = os.environ.get('ADMIN_USER')
    password = os.environ.get('ADMIN_PASS')
    if len(sys.argv) >= 2:
        username = sys.argv[1]
    if len(sys.argv) >= 3:
        password = sys.argv[2]
    if not username:
        username = input('Admin username: ').strip()
    if not password:
        password = getpass('Admin password: ')
    create_admin(username, password)


if __name__ == '__main__':
    main()
