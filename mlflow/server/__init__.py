import functools
import logging
import os
import shlex
import sys
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, send_from_directory, request, redirect, url_for, Response, session
from flask_login import login_user, login_required
from flask_oauthlib.client import OAuth

from mlflow.server import handlers
from mlflow.server.auth import GithubAuth, User, login_required_conditional
from mlflow.server.handlers import get_artifact_handler, STATIC_PREFIX_ENV_VAR, _add_static_prefix, \
    make_login_required_for_handlers
from mlflow.utils.process import exec_cmd

_logger = logging.getLogger(__name__)

# NB: These are intenrnal environment variables used for communication between
# the cli and the forked gunicorn processes.
BACKEND_STORE_URI_ENV_VAR = "_MLFLOW_SERVER_FILE_STORE"
ARTIFACT_ROOT_ENV_VAR = "_MLFLOW_SERVER_ARTIFACT_ROOT"
PROMETHEUS_EXPORTER_ENV_VAR = "prometheus_multiproc_dir"

REL_STATIC_DIR = "js/build"

app = Flask(__name__, static_folder=REL_STATIC_DIR)
STATIC_DIR = os.path.join(app.root_path, REL_STATIC_DIR)


for http_path, handler, methods in handlers.get_endpoints():
    app.add_url_rule(http_path, handler.__name__, handler, methods=methods)


if os.getenv(PROMETHEUS_EXPORTER_ENV_VAR):
    from mlflow.server.prometheus_exporter import activate_prometheus_exporter
    prometheus_metrics_path = os.getenv(PROMETHEUS_EXPORTER_ENV_VAR)
    if not os.path.exists(prometheus_metrics_path):
        os.makedirs(prometheus_metrics_path)
    activate_prometheus_exporter(app)


client_id = os.getenv('GITHUB__CLIENT_ID')
client_secret = os.getenv('GITHUB__CLIENT_SECRET')
whitelisted_team_ids = os.getenv('GITHUB__WHITELISTED_TEAM_IDS')

github_auth_enabled = client_id and client_secret and whitelisted_team_ids
github_auth = None


if github_auth_enabled:
    # In this case we activate github auth
    _logger.info(f"Enabling github authentication with the following whitelisted team IDs: {whitelisted_team_ids}.")

    whitelisted_team_ids = list(map(int, whitelisted_team_ids.split(";")))

    github_auth = GithubAuth(app, whitelisted_team_ids, client_id, client_secret)

    @app.route('/login/callback')
    def login_callback():
        _logger.info("/login/callback")
        next_url = request.args.get('state') or '/'
        _logger.info(f"Next url: {next_url}, request.args: {request.args}")
        _logger.info(f"Session: {session}\nCookies: {request.cookies}")

        response = github_auth.github_oauth.authorized_response()
        access_token = response['access_token']

        if not github_auth.has_valid_permissions(access_token):
            return "Access denied."

        # Sets the cookie in the browser
        login_user(User(1), remember=True)

        return redirect(next_url)

    @app.route('/login')
    def login():
        return "<a href='/login/authorize?next={}'> <h1> Login via Github </h1> </a>".format(request.args.get('next', None))

    @app.route('/login/authorize')
    def login_authorize():
        url_parse = urlparse(request.base_url)
        callback = urljoin(f"{url_parse.scheme}://{url_parse.netloc}", '/login/callback')
        _logger.info(f"Passing state to authorize: {request.args.get('next')}, request.args: {request.args}, callback: {callback}")
        return github_auth.github_oauth.authorize(callback=callback, state=request.args.get('next'))

    make_login_required_for_handlers(github_auth.api_login_required)


# Serve the "get-artifact" route.
@app.route(_add_static_prefix('/get-artifact'))
def serve_artifacts():
    return get_artifact_handler()


# Add health endpoint
@app.route('/health')
def health():
    return 'Healthy', 200


# We expect the react app to be built assuming it is hosted at /static-files, so that requests for
# CSS/JS resources will be made to e.g. /static-files/main.css and we can handle them here.
@app.route(_add_static_prefix('/static-files/<path:path>'))
def serve_static_file(path):
    return send_from_directory(STATIC_DIR, path)


# Serve the index.html for the React App for all other routes.
@app.route(_add_static_prefix('/'))
@login_required_conditional(github_auth_enabled, github_auth)
def serve():
    print("Call from the /, request", request.args)
    return send_from_directory(STATIC_DIR, 'index.html')


def _build_waitress_command(waitress_opts, host, port):
    opts = shlex.split(waitress_opts) if waitress_opts else []
    return ['waitress-serve'] + \
        opts + [
            "--host=%s" % host,
            "--port=%s" % port,
            "--ident=mlflow",
            "mlflow.server:app"
    ]


def _build_gunicorn_command(gunicorn_opts, host, port, workers):
    bind_address = "%s:%s" % (host, port)
    opts = shlex.split(gunicorn_opts) if gunicorn_opts else []
    return ["gunicorn"] + opts + ["-b", bind_address, "-w", "%s" % workers, "mlflow.server:app"]


def _run_server(file_store_path, default_artifact_root, host, port, static_prefix=None,
                workers=None, gunicorn_opts=None, waitress_opts=None, expose_prometheus=None):
    """
    Run the MLflow server, wrapping it in gunicorn or waitress on windows
    :param static_prefix: If set, the index.html asset will be served from the path static_prefix.
                          If left None, the index.html asset will be served from the root path.
    :return: None
    """
    env_map = {}
    if file_store_path:
        env_map[BACKEND_STORE_URI_ENV_VAR] = file_store_path
    if default_artifact_root:
        env_map[ARTIFACT_ROOT_ENV_VAR] = default_artifact_root
    if static_prefix:
        env_map[STATIC_PREFIX_ENV_VAR] = static_prefix

    if expose_prometheus:
        env_map[PROMETHEUS_EXPORTER_ENV_VAR] = expose_prometheus

    # TODO: eventually may want waitress on non-win32
    if sys.platform == 'win32':
        full_command = _build_waitress_command(waitress_opts, host, port)
    else:
        full_command = _build_gunicorn_command(gunicorn_opts, host, port, workers or 4)
    exec_cmd(full_command, env=env_map, stream_output=True)
