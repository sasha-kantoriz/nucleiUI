import os
from functools import wraps
from flask import Flask, request, Response, render_template


app = Flask(__name__, template_folder=os.path.abspath(os.path.dirname(__file__)), static_folder=os.path.abspath(os.path.dirname(__file__)))

APPLICATION_USERNAME = os.environ.get("APPLICATION_USERNAME", "admin")
APPLICATION_PASSWORD = os.environ.get("APPLICATION_PASSWORD", "AppS3cr3t")

def check_auth(username, password):
    return username == APPLICATION_USERNAME and password == APPLICATION_PASSWORD

def authenticate():
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route("/")
@requires_auth
def index():
    return render_template("index.html")
