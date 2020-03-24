### LOGIN ###
import functools
import os
from urllib.parse import urljoin

import requests
from flask import request
from flask_login import LoginManager, current_user, login_required
from flask_oauthlib.client import OAuth


GITHUB_API_BASE_URL_DEFAULT = 'https://api.github.com'
GITHUB_BASE_URL_DEFAULT = 'https://github.com'
GITHUB_AUTHORIZE_PATH = '/login/oauth/authorize'
GITHUB_USER_TEAMS_PATH = '/user/teams'
GITHUB_ACCESS_TOKEN_PATH = '/login/oauth/access_token'


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


class GithubAuth:
    def __init__(self,
                 app,
                 whitelisted_team_ids,
                 client_id,
                 client_secret,
                 secret_key=None,
                 github_base_url=None,
                 github_api_base_url=None):
        self.app = app
        self.whitelisted_team_ids = whitelisted_team_ids

        self.client_id = client_id
        self.client_secret = client_secret
        self.secret_key = secret_key if secret_key else os.urandom(24)

        self.github_base_url = github_base_url if github_base_url else GITHUB_BASE_URL_DEFAULT
        self.github_authorize_url = urljoin(self.github_base_url, GITHUB_AUTHORIZE_PATH)
        self.github_access_token_url = urljoin(self.github_base_url, GITHUB_ACCESS_TOKEN_PATH)

        self.github_api_base_url = github_api_base_url if github_api_base_url else GITHUB_API_BASE_URL_DEFAULT
        self.github_teams_url = urljoin(self.github_api_base_url, GITHUB_USER_TEAMS_PATH)

        self.login_manager = LoginManager()

        self.login_manager.login_view = "/login"

        # Load User by default
        @self.login_manager.user_loader
        def load_user(user_id):
            return User(user_id)

        self.github_oauth = OAuth(app).remote_app(
            'github_auth',
            consumer_key=self.client_id,
            consumer_secret=self.client_secret,
            request_token_params={'scope': 'user:email read:org'},
            base_url=self.github_base_url,
            request_token_url=None,
            access_token_method='POST',
            access_token_url=self.github_access_token_url,
            authorize_url=self.github_authorize_url
        )

        self.login_manager.init_app(app)
        self.app.secret_key = self.secret_key

    def set_login_view(self, url):
        self.login_manager.login_view = url

    def set_user_loader(self, user_loader):
        self.login_manager.user_callback = user_loader

    def has_valid_permissions(self, access_token):
        resp = requests.get(self.github_teams_url,
                            headers={
                                'Authorization': f'Bearer {access_token}',
                                'Accept': 'application/json'
                            })

        if resp.status_code != 200:
            return False

        team_ids = {team['id'] for team in resp.json()}
        if not team_ids.intersection(self.whitelisted_team_ids):
            # User is a part of whitelisted team, so we can authorize
            return False

        return True

    def api_login_required(self, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if current_user.is_authenticated:
                # Case when accessing via UI, because cookie is set
                return func(*args, **kwargs)

            authorization = request.headers.get('Authorization')
            if not (authorization and len(authorization.split(' ')) == 2):
                return self.login_manager.unauthorized()

            access_token = authorization.split(' ')[1]

            if self.has_valid_permissions(access_token):
                return func(*args, **kwargs)

            return self.login_manager.unauthorized()

        return wrapper


def login_required_conditional(github_auth_enabled):
    if github_auth_enabled:
        return login_required

    def decorator(f):
        return f
    return decorator
