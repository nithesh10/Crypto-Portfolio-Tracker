import smtplib
import threading
import time
import sys
sys.path.append('.')
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
from bybit import get_symbols
from database import db
from celery import Celery
from datetime import timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
# Initialization
app = Flask(__name__)
Bootstrap4(app)

app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['result_backend'] = 'redis://localhost:6379/0'
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'], backend=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)
app.config['SECRET_KEY'] = 'Surya123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Fetch a list of cryptocurrencies
response=get_symbols()
cryptos = [(crypto['name'], crypto['name']) for crypto in response]


# Models
from models import Crypto,User,Watchlist,PriceAlerts
# Forms
from forms import SignupForm,LoginForm,CryptoForm,WatchlistForm

#celery task scheduler
@celery.task
def check_price_alerts():
    print("Checking price alerts...") 
    price_alerts = PriceAlerts.query.all()
    for alert in price_alerts:
        symbol_info = get_symbol_info(alert.symbol)
        print(symbol_info)
        last_price = float(symbol_info['lastPrice'])
        if last_price >= alert.upper_limit or last_price <= alert.lower_limit:
            print("alert triggered")
            pass


celery.conf.beat_schedule = {
    'check-price-alerts': {
        'task': 'app.check_price_alerts',
        'schedule': timedelta(seconds=60),
    },
}




@app.template_filter('truncate_email')
def truncate_email(email, max_length=20):
    if len(email) <= max_length:
        return email
    else:
        half_length = max_length // 2
        start = email[:half_length]
        end = email[-half_length:]
        return start + '****' + end

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
    #price_thread = threading.Thread(target=track_prices)
    #price_thread.start()
    app.run(debug=True)
"""

def track_prices():
    with app.app_context():
        sent_email=[]
        while True:
            # Add the cryptocurrencies you want to track here
            price_alerts = PriceAlerts.query.all()
            for alert in price_alerts:
                if alert.id not in sent_email:
                    print(alert,sent_email)
                    symbol_info = get_symbol_info(alert.symbol)
                    if symbol_info:
                        # Check if the response contains data
                        symbol_data = symbol_info[0]  # Access the first dictionary in the list
                        last_price = float(symbol_data['lastPrice'])  # Access 'lastPrice'
                        price_change=float(symbol_data['price24hPcnt'])
                        print(price_change)
                        print("Last price for {}: {}".format(alert.symbol, last_price))
                        if last_price >= alert.upper_limit or last_price <= alert.lower_limit:
                            print("Alert triggered for {}".format(alert.symbol))
                            user = User.query.get(alert.user_id)
                            print("sending email to ",user.id,user.username,user.email)
                            email_body = render_template('price_alert_email.html',
                                    symbol=alert.symbol,
                                    price=last_price,
                                    percentage_change=price_change)
                            sent_email.append(alert)
                            send_email(user.email,"Price Alert Triggered",email_body)
                            
                            #db.session.delete(alert)
                            #db.session.commit()
            time.sleep(100)
"""