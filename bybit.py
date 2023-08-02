import requests
import pandas as pd



API_KEY = 'YOUR_API_KEY'
SECRET_KEY = 'YOUR_SECRET_KEY'


def get_symbols():
    response = requests.get('https://api.bybit.com/spot/v3/public/symbols', headers={'api_key': 'YourAPIKey'})
    response=response.json()['result']['list']
    return response

def get_symbol_info(symbol):
    url = f'https://api.bybit.com/v5/market/tickers'
    params = {
        'symbol': symbol,
        'category': "spot",
    }
    response = requests.get(url, params=params)
    data = response.json()['result']
    return (data['list'])
def get_candlestick_data(symbol, interval, limit):
    print(symbol,interval)
    url = f'https://api.bybit.com/v5/market/kline/'
    params = {
        'symbol': symbol,
        'interval': interval,
        'category': "spot",
    }
    response = requests.get(url, params=params)
    data = response.json()['result']
    df = pd.DataFrame(data)
    df['times'] = pd.to_datetime(df['list'].apply(lambda x: int(x[0])/1000), unit='s')
    df['open'] = df['list'].apply(lambda x: x[1])
    df['high'] = df['list'].apply(lambda x: x[2])
    df['low'] = df['list'].apply(lambda x: x[3])
    df['close'] = df['list'].apply(lambda x: x[4])
    df = df.drop(['category', 'symbol', 'list'], axis=1)
    df = df.sort_values(by='times')
    print(df)
    
    return df