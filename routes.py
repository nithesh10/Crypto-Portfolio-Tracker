from flask import render_template, redirect, url_for, flash
from flask_login import current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, SelectField
from wtforms.validators import DataRequired, EqualTo, Email, Regexp, ValidationError
from bybit import get_candlestick_data, get_symbol_info
from database import db
from forms import WatchlistForm,SignupForm,LoginForm
from models import Crypto, PriceAlerts, User, Watchlist
from app import app, cryptos
from flask import Flask, render_template, jsonify,request
import pandas as pd
# Routes

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    global saved_symbol
    watchlist_form = WatchlistForm()
    watchlist = Watchlist.query.filter_by(user_id=current_user.id).all()

    if watchlist_form.validate_on_submit():
        crypto = Watchlist(
            user_id=current_user.id,
            crypto_name=watchlist_form.crypto.data,
            lower_limit=watchlist_form.lower_limit.data,
            upper_limit=watchlist_form.upper_limit.data
        )
        db.session.add(crypto)
        db.session.commit()
        flash('Crypto added to watchlist!')
        return redirect(url_for('index'))
    selected_crypto = request.args.get('crypto',"BTCUSDT") 
    symbol = selected_crypto  # Replace with your desired trading pair
    timeline = (request.args.get('timeline', '5'))  # Get selected timeline, default 5 minutes
    interval = f'{timeline}'  # Convert to string for API request
    limit = 100  # Number of data points to fetch
    data = get_candlestick_data(symbol, interval, limit)

    # Format the x-axis labels based on the selected timeline
    data['times'] = pd.to_datetime(data['times'])
    data['times_d'] = pd.to_datetime(data['times'])
    data['times'] = data['times'].dt.strftime('%Y-%m-%d %H:%M:%S')
    saved_symbol=selected_crypto
    return render_template('index.html', watchlist_form=watchlist_form, watchlist=watchlist, candlestick_data=data.to_dict(orient='records'))

@app.route('/candlestick_data')
def candlestick_data():
    global saved_symbol
    selected_crypto = request.args.get('crypto',"BTCUSDT") 
    if(selected_crypto=="None"):
        selected_crypto=saved_symbol
    symbol = selected_crypto  # Replace with your desired trading pair
    timeline = (request.args.get('timeline', '5'))  # Get selected timeline, default 5 minutes
    interval = f'{timeline}'  # Convert to string for API request
    limit = 100  # Number of data points to fetch
    data = get_candlestick_data(symbol, interval, limit)

    # Format the x-axis labels based on the selected timeline
    data['times'] = pd.to_datetime(data['times'])
    data['times_d'] = pd.to_datetime(data['times'])
   
    data['times'] = data['times'].dt.strftime('%Y-%m-%d %H:%M:%S')
    saved_symbol=selected_crypto
    return jsonify(data.to_dict(orient='records'))

@app.route('/symbol_info', methods=['GET'])
def symbol_info():
    symbol = request.args.get('symbol', 'BTCUSDT')
    symbol_info = get_symbol_info(symbol)
    return jsonify(symbol_info)

@app.route('/add_price_alert', methods=['GET', 'POST'])
def add_price_alert():
    data = request.get_json()
    user_id = current_user.id
    symbol = data.get('crypto_name', 'BTCUSDT')
    lower_limit = data.get('lower_limit')
    upper_limit = data.get('upper_limit')
    price_alert = PriceAlerts(user_id=user_id, symbol=symbol, lower_limit=lower_limit, upper_limit=upper_limit)
    db.session.add(price_alert)
    db.session.commit()
    return jsonify({'message': 'Price alert added successfully.'}), 200

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