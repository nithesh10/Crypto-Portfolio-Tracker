from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
import requests
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, EqualTo, Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap4
from wtforms.validators import Regexp, ValidationError
from wtforms import StringField, PasswordField, SubmitField, SelectField


# Initialization
app = Flask(__name__)
Bootstrap4(app)
app.config['SECRET_KEY'] = 'Surya123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# fetch a list of cryptocurrencies
response = requests.get('https://api.bybit.com/v2/public/symbols', headers={'api_key': 'YourAPIKey'})
cryptos = [(crypto['name'], crypto['name']) for crypto in response.json()['result']]


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    cryptos = db.relationship('Crypto', backref='user', lazy='dynamic')
    watchlist = db.relationship('Watchlist', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    crypto_name = db.Column(db.String(64))
class WatchlistForm(FlaskForm):
    crypto = SelectField('Cryptocurrency', choices=cryptos)
    crypto_name=crypto.name
    submit = SubmitField('Submit')

@app.route('/add_to_watchlist', methods=['GET', 'POST'])
@login_required
def add_to_watchlist():
    form = WatchlistForm()
    if form.validate_on_submit():
        crypto = Watchlist(user_id=current_user.id, crypto_name=form.crypto.data)
        db.session.add(crypto)
        db.session.commit()
        flash('Crypto added to watchlist!')
        return redirect(url_for('dashboard'))
    return render_template('add_to_watchlist.html', form=form)


@app.route('/remove_from_watchlist/<crypto_name>', methods=['POST'])
@login_required
def remove_from_watchlist(crypto_name):
    crypto = Watchlist.query.filter_by(user_id=current_user.id, crypto_name=crypto_name).first()
    if crypto:
        db.session.delete(crypto)
        db.session.commit()
    return redirect(url_for('index'))


@app.route('/dashboard', methods=['GET', 'POST'])

@login_required
def dashboard():
    watchlist = Watchlist.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', watchlist=watchlist)

class Crypto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Forms
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        EqualTo('password2', message='Passwords must match.'),
        Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', 
               message='Password should be at least 8 characters long, contain an uppercase and lowercase letter, a digit, and a special character.')
    ])
    password2 = PasswordField('Repeat Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class CryptoForm(FlaskForm):
    cryptos = SelectMultipleField('Select Cryptocurrencies', choices=cryptos, validators=[DataRequired()])
    submit = SubmitField('Submit')
# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    form = CryptoForm()
    if form.validate_on_submit():
        # save the selected cryptocurrencies and redirect to the tracking page
        pass
    return render_template('index.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already taken. Please choose a different one.')
            return redirect(url_for('signup'))
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash('Registered User With this email exists. Please Login')
            return redirect(url_for('login'))
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login')) 
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
with app.app_context():
    db.create_all()
if __name__ == '__main__':
    app.run(debug=True)

