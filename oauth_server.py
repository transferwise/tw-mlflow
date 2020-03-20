from urllib.parse import urlencode, urljoin

import requests
from flask import Flask, redirect, url_for, request, session
from flask_login import LoginManager, login_user, login_required

'''
http://test-mlflow.tw.ee:5000/login/callback
'''

client_id = 'caddc4b1806fd856728c'
client_secret = 'e6b29f3777bd4c796970e615d37f427cc161763b'

# Should be a random string
APP_SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

base_url = 'https://github.com/login/oauth/authorize'
params = {
    'client_id': client_id,
    'redirect_uri': 'http://localhost:8080/login/callback',
    'scope': 'user:email read:org'
}

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

# We should be using team ids, because they are uniques
# Team names are not uniques (they are unique for particular organization only)
# You can get id of the team by calling https://api.github.com/user/teams and finding your team
WHITELISTED_TEAM_IDS = {
    3662422,  # General ML team
    3662421,  # NLP team
}


@app.route('/login/callback')
def login_callback():
    print("Redirected here!")
    code = request.args.get('code')

    resp = requests.post("https://github.com/login/oauth/access_token",
                         json={
                             'client_id': client_id,
                             'client_secret': client_secret,
                             'code': code
                         },
                         headers={
                             'Accept': 'application/json'
                         })

    access_token = resp.json()['access_token']
    token_type = resp.json()['token_type']

    resp = requests.get('https://api.github.com/user/teams',
                        headers={
                            'Authorization': f'{token_type} {access_token}',
                            'Accept': 'application/json'
                        })

    team_ids = {team['id'] for team in resp.json()}
    if not team_ids.intersection(WHITELISTED_TEAM_IDS):
        # User is a part of whitelisted team, so we can authorize
        return "Access denied."

    # Sets the cookie in the browser
    login_user(User(1))
    return "Authorized!"


@app.route('/private/info')
@login_required
def private_info():
    return "Here is your access to private info!"


@app.route('/public/info')
def public_info():
    return "Here is your access to public info!"


@app.route('/login')
def login():
    return f"<a href='{base_url}?{urlencode(params)}'> <h1> Login via Github </h1> </a>"


@app.route('/')
@login_required
def root():
    return 'This is the home page.'
    # return redirect(f"{base_url}?{urlencode(params)}")


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User:
    def __init__(self, user_id):
        self.user_id = str(user_id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.user_id


@login_manager.user_loader
def load_user(user_id):
    print(f"load_user called with user_id={user_id}")
    return User(user_id)


app.run('127.0.0.1', port=8080)
