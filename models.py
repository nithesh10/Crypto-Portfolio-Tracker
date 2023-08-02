from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from database import db
from sqlalchemy import Column, Integer, String, Float
class Crypto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    cryptos = db.relationship('Crypto', backref='user', lazy='dynamic')
    watchlist = db.relationship('Watchlist', backref='user', lazy='dynamic')
    receive_portfolio_email = db.Column(db.Boolean, default=False)  # Add this field


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    crypto_name = db.Column(db.String(64))
    lower_limit = Column(Float)
    upper_limit = Column(Float)
class PriceAlerts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='price_alerts')
    symbol = db.Column(db.String(10), nullable=False)
    lower_limit = db.Column(db.Float, nullable=False)
    upper_limit = db.Column(db.Float, nullable=False)
