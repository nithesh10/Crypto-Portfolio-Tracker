import smtplib
import threading
import time
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

def track_prices():
    with app.app_context():
        while True:
            # Add the cryptocurrencies you want to track here
            price_alerts = PriceAlerts.query.all()
            for alert in price_alerts:
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
                        send_email(user.email,"Price Alert Triggered",email_body)
                        db.session.delete(alert)
                        db.session.commit()
            time.sleep(5)

def send_email(recipient_email, subject, body):
    sender_email = "a.nitheshkumar@gmail.com"
    sender_password = "tsovmyxrsykdtcot"
    try:
        # creates SMTP session
        s = smtplib.SMTP('smtp.gmail.com', 587)

        # start TLS for security
        s.starttls()

        # Authentication
        s.login(sender_email, sender_password)
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient_email
        # Create the email message
        msg.attach(MIMEText(body, 'html'))
        

        # sending the mail
        s.sendmail(sender_email, recipient_email, msg.as_string())

        # terminating the session
        s.quit()

        print("Email sent successfully.")
    except Exception as e:
        print("Error: ", e)


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
    price_thread = threading.Thread(target=track_prices)
    price_thread.start()
    app.run(debug=True)
