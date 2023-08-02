from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap4
import requests
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, SelectField
from wtforms.validators import DataRequired, EqualTo, Email, Regexp, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from database import db
# Initialization
app = Flask(__name__)
Bootstrap4(app)
app.config['SECRET_KEY'] = 'Surya123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Fetch a list of cryptocurrencies
response = requests.get('https://api.bybit.com/v2/public/symbols', headers={'api_key': 'YourAPIKey'})
cryptos = [(crypto['name'], crypto['name']) for crypto in response.json()['result']]


# Models
from models import Crypto,User,Watchlist
# Forms
from forms import SignupForm,LoginForm,CryptoForm,WatchlistForm

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
from routes import *

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
