from urllib.parse import urlencode, urljoin

import requests
from flask import Flask, redirect, url_for, request, session
from flask_login import LoginManager, login_user, login_required
from flask_oauthlib.client import OAuth

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

github_base_url='github.com'


github_oauth = OAuth(app).remote_app(
    'github_auth',
    consumer_key=client_id,
    consumer_secret=client_secret,
    # need read:org to get team member list
    request_token_params={'scope': 'user:email read:org'},
    base_url=github_base_url,
    request_token_url=None,
    access_token_method='POST',
    access_token_url=''.join(['https://',
                              github_base_url,
                              '/login/oauth/access_token']),
    authorize_url=''.join(['https://',
                           github_base_url,
                           '/login/oauth/authorize']))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.route('/login/callback')
def login_callback():
    next_url = request.args.get('state')
    print(f"Next url: {next_url}, request.args: {request.args}")

    response = github_oauth.authorized_response()
    print(response)

    access_token = response['access_token']

    resp = requests.get('https://api.github.com/user/teams',
                        headers={
                            'Authorization': f'Bearer {access_token}',
                            'Accept': 'application/json'
                        })

    team_ids = {team['id'] for team in resp.json()}
    if not team_ids.intersection(WHITELISTED_TEAM_IDS):
        # User is a part of whitelisted team, so we can authorize
        return "Access denied."

    # Sets the cookie in the browser
    login_user(User(1))
    return redirect(next_url)


@app.route('/private/info')
@login_required
def private_info():
    return "Here is your access to private info!"


@app.route('/public/info')
def public_info():
    return "Here is your access to public info!"


@app.route('/login/authorize')
def login_autorize():
    callback = params['redirect_uri']
    print(f"Passing state to authorize: {request.args.get('next')}, request.args: {request.args}")
    return github_oauth.authorize(callback=callback, state=request.args.get('next'))


@app.route('/login')
def login():
    return "<a href='/login/authorize?next={}'> <h1> Login via Github </h1> </a>".format(request.args.get('next', url_for('private_info')))


@app.route('/')
@login_required
def root():
    return 'This is the home page.'


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
