import hashlib
import json
import mimetypes
import os
import re
import urllib.parse
import uuid

import jinja2


JINJA_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader('templates'),
    autoescape=True,
)


def hashed_thing(thing):
    # XXX: This isn't strong enough for real password hashing, but good enough
    # for the usernames and passwords in this demo.
    return str(hashlib.sha256(
        (thing + 'ThisIsASecretSaltButNotAFlag').encode('UTF-8')
    ).hexdigest())[:20]


def user_data_path(username):
    hashed = hashed_thing(username)
    return os.path.join('data', 'users', hashed + '.json')


def load_user(username):
    try:
        with open(user_data_path(username)) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save_user(username, data):
    with open(user_data_path(username), 'w') as f:
        return json.dump(data, f, indent=4, sort_keys=True)


class Request:

    def __init__(self, environ):
        self._environ = environ
        self._request_body = environ['wsgi.input'].read()

    @property
    def path(self):
        return self._environ['PATH_INFO']

    @property
    def method(self):
        return self._environ['REQUEST_METHOD']

    @property
    def post_params(self):
        return urllib.parse.parse_qs(self._request_body.decode('UTF-8'))


class Response:

    def __init__(self, *, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers

    def __call__(self, environ, start_response):
        start_response(self.status, self.headers)
        return [self.body]

    @classmethod
    def from_template(cls, path, args=None):
        if args is None:
            args = {}
        html = JINJA_ENV.get_template(path).render(**args)
        return cls(
            status='200 OK',
            body=html.encode('UTF-8'),
            headers=(
                ('Content-Type', 'text/html; charset=utf-8'),
            ),
        )


def view_home(request, match):
    return Response.from_template('index.jinja2')


def view_register(request, match):
    if request.method == 'POST':
        # TODO: could this be a cool thing? re.match without the $?
        valid_re = '[a-z]{3,20}$'
        username, = request.post_params['username']
        if not re.match(valid_re, username):
            error = 'Username must match regex: ' + valid_re
        else:
            user = load_user(username)
            if user is not None:
                error = 'Username is already taken.'
            else:
                password = str(uuid.uuid4())
                data = {
                    'username': username,
                    'hashed_password': hashed_thing(password),
                }
                save_user(username, data)
                return Response.from_template(
                    'account_created.jinja2',
                    {'username': username, 'password': password},
                )
    else:
        error = None

    return Response.from_template(
        'register.jinja2',
        {'error': error},
    )


def view_static(request, match):
    name = match.group(1)
    guessed = mimetypes.guess_type(name)
    if guessed:
        mimetype, _ = guessed
    else:
        mimetype = 'application/octet-stream'

    with open(os.path.join('static', name), 'rb') as f:
        return Response(
            status=b'200 OK',
            body=f.read(),
            headers=(),
        )


URL_MAPPING = (
    ('^/$', view_home),
    ('^/register$', view_register),
    ('^/(main\.css|meyer\.css)$', view_static),
)
URL_MAPPING = tuple(
    (re.compile(pattern), view) for pattern, view in URL_MAPPING
)


def execute(request):
    for pattern, view in URL_MAPPING:
        m = pattern.match(request.path)
        if m:
            return view(request, m)
    else:
        return Response(
            status='404 Not Found',
            body=b'404 Not Found',
            headers=(),
        )


def app(environ, start_response):
    return execute(Request(environ))(environ, start_response)
