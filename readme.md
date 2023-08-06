# Cryptocurrency Portfolio Tracker

## Description
Cryptocurrency Portfolio Tracker is a web application built with Flask that allows users to track their cryptocurrency holdings and set price alerts for specific cryptocurrencies. It also offers a real-time price update feature and sends price alert emails when the price of a tracked cryptocurrency crosses the defined limits.

## Features
- User authentication and registration system.
- Add, edit, and delete cryptocurrency holdings in your portfolio.
- Set price alerts for specific cryptocurrencies.
- Real-time price updates for tracked cryptocurrencies.
- Email notifications for price alerts.

## Prerequisites
- Docker installed on your system.

## Installation and Usage

1. Clone the repository to your local machine:

[git clone https://github.com/nithesh10/Crypto-Portfolio-Tracker.git]

2. Navigate to the project directory:

   [cd cryptocurrency-portfolio-tracker]
   
3. Build the Docker image:
   docker build -t cryptocurrency-portfolio .
   
4. Run the Docker container:
   docker run -p 5000:5000 cryptocurrency-portfolio

5. Open your web browser and visit `http://localhost:5000` to access the application.

## Configuration

- The application uses a SQLite database to store user and cryptocurrency data. You can change the database configuration in `app.py` if needed.

- Email notifications for price alerts require configuring a valid email service in the Flask app. Set the following environment variables with your email credentials:

export MAIL_SERVER=your-email-smtp-server
export MAIL_PORT=your-email-smtp-port
export MAIL_USERNAME=your-email-username
export MAIL_PASSWORD=your-email-password
export MAIL_DEFAULT_SENDER=your-email-address

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Author
- Nithesh Kumar A
![image](https://github.com/nithesh10/Crypto-Portfolio-Tracker/assets/83530216/1425f7ab-8ccb-461b-b4db-07d793788d85)

