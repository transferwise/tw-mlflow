import functools
import os
import shlex
import sys

import requests
from flask import Flask, send_from_directory, request, redirect, url_for, Response
from flask_login import login_user, login_required
from flask_oauthlib.client import OAuth

from mlflow.server import handlers
from mlflow.server.auth import User, has_valid_permissions, APP_SECRET_KEY, login_manager
from mlflow.server.handlers import get_artifact_handler, STATIC_PREFIX_ENV_VAR, _add_static_prefix
from mlflow.utils.process import exec_cmd

# NB: These are intenrnal environment variables used for communication between
# the cli and the forked gunicorn processes.
BACKEND_STORE_URI_ENV_VAR = "_MLFLOW_SERVER_FILE_STORE"
ARTIFACT_ROOT_ENV_VAR = "_MLFLOW_SERVER_ARTIFACT_ROOT"
PROMETHEUS_EXPORTER_ENV_VAR = "prometheus_multiproc_dir"

REL_STATIC_DIR = "js/build"

app = Flask(__name__, static_folder=REL_STATIC_DIR)
STATIC_DIR = os.path.join(app.root_path, REL_STATIC_DIR)

app.secret_key = APP_SECRET_KEY

for http_path, handler, methods in handlers.get_endpoints():
    app.add_url_rule(http_path, handler.__name__, handler, methods=methods)


if os.getenv(PROMETHEUS_EXPORTER_ENV_VAR):
    from mlflow.server.prometheus_exporter import activate_prometheus_exporter
    prometheus_metrics_path = os.getenv(PROMETHEUS_EXPORTER_ENV_VAR)
    if not os.path.exists(prometheus_metrics_path):
        os.makedirs(prometheus_metrics_path)
    activate_prometheus_exporter(app)

client_id = 'caddc4b1806fd856728c'
client_secret = 'e6b29f3777bd4c796970e615d37f427cc161763b'
APP_SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

base_url = 'https://github.com/login/oauth/authorize'
github_base_url = 'github.com'

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

login_manager.init_app(app)


@app.route('/login/callback')
def login_callback():
    print("Message from the callback!")
    next_url = request.args.get('state') or '/'
    print(f"Next url: {next_url}, request.args: {request.args}")

    response = github_oauth.authorized_response()
    print(response)

    access_token = response['access_token']

    if not has_valid_permissions(access_token):
        return "Access denied."

    # Sets the cookie in the browser
    login_user(User(1))
    return redirect(next_url)


@app.route('/login')
def login():
    return "<a href='/login/authorize?next={}'> <h1> Login via Github </h1> </a>".format(request.args.get('next', None))


@app.route('/login/authorize')
def login_authorize():
    callback = 'http://127.0.0.1:5000/login/callback'
    print(f"Passing state to authorize: {request.args.get('next')}, request.args: {request.args}")
    return github_oauth.authorize(callback=callback, state=request.args.get('next'))


# Serve the "get-artifact" route.
@app.route(_add_static_prefix('/get-artifact'))
def serve_artifacts():
    return get_artifact_handler()


# We expect the react app to be built assuming it is hosted at /static-files, so that requests for
# CSS/JS resources will be made to e.g. /static-files/main.css and we can handle them here.
@app.route(_add_static_prefix('/static-files/<path:path>'))
def serve_static_file(path):
    return send_from_directory(STATIC_DIR, path)


# Serve the index.html for the React App for all other routes.
@app.route(_add_static_prefix('/'))
@login_required
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
