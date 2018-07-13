import cgi
import hashlib
import io
import json
import mimetypes
import os
import re
import shutil
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


def user_data_path(username, hashed=False):
    if not hashed:
        hashed = hashed_thing(username)
    else:
        hashed = username
    return os.path.join('data', 'users', hashed + '.json')


def load_user(username, hashed=False):
    try:
        with open(user_data_path(username, hashed=hashed)) as f:
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
        self.fs = cgi.FieldStorage(fp=io.BytesIO(self._request_body), environ=environ)

    @property
    def path(self):
        return self._environ['PATH_INFO']

    @property
    def method(self):
        return self._environ['REQUEST_METHOD']

    @property
    def post_params(self):
        return urllib.parse.parse_qs(self._request_body.decode('UTF-8'))

    def header(self, key):
        return self._environ.get('HTTP_' + key.upper().replace('-', '_'))

    @property
    def cookies(self):
        cookies = self.header('Cookie')
        if cookies:
            return {
                k: v
                for k, v
                in (x.split('=', 1) for x in cookies.split('; '))
            }
        else:
            return {}


class Response:

    def __init__(self, *, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers

    def __call__(self, environ, start_response):
        start_response(self.status, self.headers)
        return [self.body]

    @classmethod
    def from_template(cls, request, path, args=None, headers=()):
        if args is None:
            args = {}
        html = JINJA_ENV.get_template(path).render(request=request, **args)
        return cls(
            status='200 OK',
            body=html.encode('UTF-8'),
            headers=(
                ('Content-Type', 'text/html; charset=utf-8'),
            ) + headers,
        )

    @classmethod
    def bad_request(cls):
        return cls(
            status='400 Bad Request',
            body=b'400 Bad Request',
            headers=(),
        )


def view_home(request, match):
    return Response.from_template(request, 'index.jinja2')


def view_register(request, match):
    if request.method == 'POST':
        # TODO: could this be a cool thing? re.match without the $?
        valid_re = '[a-z]{3,20}$'
        username, = request.post_params.get('username', ('',))
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
                request.user = data
                save_user(username, data)
                return Response.from_template(
                    request,
                    'account_created.jinja2',
                    {'username': username, 'password': password},
                    headers=(
                        ('Set-Cookie', 'session=' + hashed_thing(username) + '; Max-Age=31556926'),
                    ),
                )
    else:
        error = None

    return Response.from_template(
        request,
        'register.jinja2',
        {'error': error},
    )


def view_login(request, match):
    if request.method == 'POST':
        username, = request.post_params.get('username', ('',))
        password, = request.post_params.get('password', ('',))
        user = load_user(username)
        if user is None:
            error = 'Username does not exist.'
        else:
            if hashed_thing(password) != user['hashed_password']:
                error = 'User exists, but you used the wrong password.'
            else:
                return Response(
                    status='302 Found',
                    body=b'',
                    headers=(
                        ('Location', '/'),
                        ('Set-Cookie', 'session=' + hashed_thing(username) + '; Max-Age=31556926'),
                    ),
                )
    else:
        error = None

    return Response.from_template(
        request,
        'login.jinja2',
        {'error': error},
    )


def view_logout(request, match):
    return Response(
        status='302 Found',
        body=b'',
        headers=(
            ('Location', '/'),
            ('Set-Cookie', 'session=; Max-Age=0'),
        ),
    )


def view_upload(request, match):
    if request.method != 'POST':
        return Response.bad_request()

    # TODO: fix
    upload = request.fs['file']
    filename = upload.filename
    with open(os.path.join('data', 'uploads', filename), 'wb') as f:
        shutil.copyfileobj(upload.file, f)

    return Response(
        status='302 Found',
        body=b'',
        headers=(
            ('Location', '/data/uploads/' + filename),
        ),
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
    ('^/login$', view_login),
    ('^/logout$', view_logout),
    ('^/upload$', view_upload),
    ('^/(main\.css|meyer\.css)$', view_static),
    ('^/(data/(?:uploads|user)/[^/]+)$', view_data),
)
URL_MAPPING = tuple(
    (re.compile(pattern), view) for pattern, view in URL_MAPPING
)


def execute(request):
    session = request.cookies.get('session')
    if session is not None:
        user = load_user(session, hashed=True)
        request.user = user

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
