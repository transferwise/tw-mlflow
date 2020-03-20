### LOGIN ###
import functools

import requests
from flask import request
from flask_login import LoginManager, current_user
from flask_oauthlib.client import OAuth

client_id = 'caddc4b1806fd856728c'
client_secret = 'e6b29f3777bd4c796970e615d37f427cc161763b'
APP_SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

base_url = 'https://github.com/login/oauth/authorize'

WHITELISTED_TEAM_IDS = {
    3662422,  # General ML team
    3662421,  # NLP team
}

github_base_url = 'github.com'


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


def has_valid_permissions(access_token):
    resp = requests.get('https://api.github.com/user/teams',
                        headers={
                            'Authorization': f'Bearer {access_token}',
                            'Accept': 'application/json'
                        })

    if resp.status_code != 200:
        return False

    team_ids = {team['id'] for team in resp.json()}
    if not team_ids.intersection(WHITELISTED_TEAM_IDS):
        # User is a part of whitelisted team, so we can authorize
        return False

    return True


login_manager = LoginManager()
login_manager.login_view = 'http://localhost:5000/login'


@login_manager.user_loader
def load_user(user_id):
    print(f"load_user called with user_id={user_id}")
    return User(user_id)


def api_login_required(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            # Case when accessing via UI, because cookie is set
            return func(*args, **kwargs)

        authorization = request.headers.get('Authorization')
        if not (authorization and len(authorization.split(' ')) == 2):
            return login_manager.unauthorized()

        access_token = authorization.split(' ')[1]

        if has_valid_permissions(access_token):
            return func(*args, **kwargs)

        return login_manager.unauthorized()

    return wrapper