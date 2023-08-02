# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, SelectField
from wtforms.validators import DataRequired, EqualTo, Email, Regexp, ValidationError
import requests
from models import User
from wtforms import StringField, FloatField
from bybit import *
# fetch a list of cryptocurrencies
response=get_symbols()
cryptos = [(crypto['name'], crypto['name']) for crypto in response]

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

class WatchlistForm(FlaskForm):
    crypto = SelectField('Cryptocurrency', choices=cryptos)
    submit = SubmitField('Submit')
    lower_limit = FloatField('Lower Price Limit')
    upper_limit = FloatField('Upper Price Limit')
