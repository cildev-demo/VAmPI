import datetime
import jwt
from sqlalchemy.orm import relationship
from config import db, vuln_app
from app import vuln, alive
from models.books_model import Book
from random import randrange
from sqlalchemy.sql import text
from werkzeug.security import generate_password_hash, check_password_hash


class _PasswordHash:
    __slots__ = ('_hash',)

    def __init__(self, password_hash):
        self._hash = password_hash

    def __eq__(self, other):
        if isinstance(other, _PasswordHash):
            return self._hash == other._hash
        if not isinstance(other, str):
            return NotImplemented
        return check_password_hash(self._hash, other)

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(self._hash)

    def __str__(self):
        return self._hash

    def __repr__(self):
        return '<password hash>'


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column('password', db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    books = relationship("Book", order_by=Book.id, back_populates="user")

    def __init__(self, username, password, email, admin=False):
        self.username = username
        self.email = email
        if isinstance(password, _PasswordHash):
            self.password_hash = password._hash
        else:
            self.password_hash = generate_password_hash(str(password), method='pbkdf2:sha256')
        self.admin = admin

    @property
    def password(self):
        return _PasswordHash(self.password_hash)

    @password.setter
    def password(self, value):
        if isinstance(value, _PasswordHash):
            self.password_hash = value._hash
        else:
            self.password_hash = generate_password_hash(str(value), method='pbkdf2:sha256')

    def __repr__(self):
        return f'{{"username": "{self.username}", "email": "{self.email}"}}'

    def encode_auth_token(self, user_id):
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=alive),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                vuln_app.app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, vuln_app.app.config.get('SECRET_KEY'), algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return {'error': 'Signature expired. Please log in again.'}
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token. Please log in again.'}

    def json(self):
        return {'username': self.username, 'email': self.email}

    def json_debug(self):
        return {'username': self.username, 'email': self.email, 'admin': self.admin}

    @staticmethod
    def get_all_users():
        return [User.json(user) for user in User.query.all()]

    @staticmethod
    def get_all_users_debug():
        return [User.json_debug(user) for user in User.query.all()]

    @staticmethod
    def get_user(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def register_user(username, password, email, admin=False):
        new_user = User(username=username, password=password, email=email, admin=admin)
        randomint = str(randrange(100))
        new_user.books = [Book(book_title="bookTitle" + randomint, secret_content="secret for bookTitle" + randomint)]
        db.session.add(new_user)
        db.session.commit()

    @staticmethod
    def delete_user(username):
        done = User.query.filter_by(username=username).delete()
        db.session.commit()
        return done

    @staticmethod
    def init_db_users():
        User.register_user("name1", "pass1", "mail1@mail.com", False)
        User.register_user("name2", "pass2", "mail2@mail.com", False)
        User.register_user("admin", "pass1", "admin@mail.com", True)
