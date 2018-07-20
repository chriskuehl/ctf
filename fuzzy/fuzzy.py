import cgi
import hashlib
import io
import ipaddress
import json
import mimetypes
import os
import re
import requests
import shutil
import socket
import urllib.parse
import uuid

import jinja2


JINJA_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader('templates'),
    autoescape=True,
)
SECRET_FLAG_TWO = 'TODO: flag'


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


def save_user(username, data, hashed=False):
    with open(user_data_path(username, hashed=hashed), 'w') as f:
        return json.dump(data, f, indent=4, sort_keys=True)


class Request:

    user = None
    username_hashed = None

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
    def bad_request(cls, body=b'400 Bad Request'):
        return cls(
            status='400 Bad Request',
            body=body,
            headers=(),
        )


def view_home(request, match):
    return Response.from_template(request, 'index.jinja2')


def view_register(request, match):
    if request.method == 'POST':
        # TODO: could this be a cool thing? re.match without the $?
        valid_re = '^[a-z]{3,20}'
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
                    'hashed_password': hashed_thing(password),
                    'is_admin': False,
                    'theme': 'green',
                    'welcome': (
                        'Welcome, {request.user[display_name]}! '
                        "Thanks for creating an account!"
                    ),
                    'display_name': username,
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


def view_settings(request, match):
    if request.user is None:
        return Response.bad_request(b'Log in first!')

    error = None

    if request.method == 'POST':
        display_name, = request.post_params.get('displayname', ('',))
        theme, = request.post_params.get('theme', ('',))
        welcome, = request.post_params.get('welcome', ('',))

        if not 3 <= len(display_name) <= 20:
            error = 'Display name must be between 3 and 20 characters long.'

        if theme not in {'default', 'green', 'blue'}:
            error = 'Invalid theme selection.'

        if not 3 <= len(welcome) <= 200:
            error = 'Welcome message must be between 3 and 200 characters long.'

        if error is None:
            request.user['display_name'] = display_name
            request.user['theme'] = theme
            request.user['welcome'] = welcome
            save_user(request.username_hashed, request.user, hashed=True)

    return Response.from_template(
        request,
        'settings.jinja2',
        {'error': error},
    )


def view_upload(request, match):
    if request.user is None:
        return Response.bad_request(b'Log in first!')

    if request.method != 'POST':
        return Response.bad_request()

    if 'file' not in request.fs:
        return Response.bad_request(b'Missing `file`.')

    upload = request.fs['file']

    if upload.file is None:
        return Response.bad_request(b'`file` must actually be a file.')

    if upload.filename is None:
        filename = 'unknown-filename-' + str(uuid.uuid4())
    else:
        filename = upload.filename

    dest_filepath = os.path.abspath(os.path.join('data', 'uploads', filename))

    # XXX: Path traversal expected, but let's prevent writing outside of
    # `data`.
    if not dest_filepath.startswith(os.path.abspath('data') + '/'):
        return Response.bad_request(b'Bad upload path')

    if not os.path.exists(os.path.dirname(dest_filepath)):
        return Response.bad_request(b'Bad upload path')

    if os.path.isdir(dest_filepath):
        return Response.bad_request(b'Bad upload path')

    with open(dest_filepath, 'wb') as f:
        shutil.copyfileobj(upload.file, f)

    return Response(
        status='302 Found',
        body=b'',
        headers=(
            ('Location', '/data/uploads/' + filename),
        ),
    )


def view_upload_url(request, match):
    if request.user is None:
        return Response.bad_request(b'Log in first!')

    if request.method != 'POST':
        return Response.bad_request()

    # TODO: fix
    url, = request.post_params.get('url', ('',))

    if ':' not in url:
        url = 'http://' + url


    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in {'http', 'https'}:
        return Response.bad_request(b'Bad URL scheme')

    if not parsed.netloc:
        return Response.bad_request(b'Bad URL!')

    # XXX: Here's where the sketchy validation happens...
    # You can use another DNS name, or a slightly different IP format, or IPv6, etc.
    if 'localhost' in parsed.netloc:
        return Response.bad_request(b"Nice try, but you can't steal our localhost secrets!")

    bad_re = '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:$|:)'
    if re.match(bad_re, parsed.netloc):
        return Response.bad_request(
            "Sorry, you can't upload from an IP (matches regex: {})".format(
                bad_re,
            ).encode('UTF-8')
        )

    # We do a bit better whitelisting here just to prevent too much silliness
    # (though... no guarantees it's perfect)
    host, _, port = parsed.netloc.partition(':')
    if not port:
        port = 80
    try:
        ip = socket.gethostbyname(host)
    except socket.error as ex:
        return Response.bad_request(b'Bad upload domain: ' + str(ex).encode('UTF-8'))

    ip = ipaddress.IPv4Address(ip)
    if (
            ip in ipaddress.ip_network('10.0.0.0/8') or
            ip in ipaddress.ip_network('172.16.0.0/12') or
            ip in ipaddress.ip_network('192.168.0.0/16') or
            ip in ipaddress.ip_network('169.254.0.0/16')
    ):
        # lie to the user a little
        return Response.bad_request(
            b'Bad upload domain: Bad upload domain: [Errno -2] Name or service not known',
        )

    headers = {'Host': parsed.netloc}
    parsed = parsed._replace(netloc='{}:{}'.format(ip, port))
    url = urllib.parse.urlunparse(parsed)
    _, ext = os.path.splitext(url)
    if ext:
        ext = '.' + re.sub('[^0-9a-zA-Z]', 'X', ext)
    filename = str(uuid.uuid4()) + ext
    with open(os.path.join('data', 'uploads', filename), 'wb') as f:
        try:
            req = requests.get(url, timeout=1, headers=headers)
        except requests.exceptions.RequestException as ex:
            return Response.bad_request(b'Error downloading file: ' + str(ex).encode('UTF-8'))

        if req.status_code != 200:
            return Response.bad_request(
                'Bad status from URL: {}'.format(req.status_code).encode('UTF-8'),
            )

        f.write(req.content)

    return Response(
        status='302 Found',
        body=b'',
        headers=(
            ('Location', '/data/uploads/' + filename),
        ),
    )


def _view_static_files(path):
    guessed = mimetypes.guess_type(path)
    if guessed[0]:
        mimetype, _ = guessed
    else:
        mimetype = 'application/octet-stream'

    try:
        with open(path, 'rb') as f:
            return Response(
                status='200 OK',
                body=f.read(),
                headers=(
                    ('Content-Type', mimetype),
                ),
            )
    except FileNotFoundError:
        return Response(
            status='404 Not Found',
            body=b'404 Not Found',
            headers=(),
        )


def view_static(request, match):
    return _view_static_files(os.path.join('static', match.group(1)))


def view_data(request, match):
    return _view_static_files(match.group(1))


def view_user_info(request, match):
    if request.user:
        return Response(
            status='302 Found',
            body=b'',
            headers=(
                ('Location', '/data/users/' + request.username_hashed + '.json'),
            ),
        )
    else:
        return Response(
            status='200 OK',
            body=b'{}',
            headers=(
                ('Content-Type', 'application/json'),
            ),
        )


URL_MAPPING = (
    ('^/$', view_home),
    ('^/register$', view_register),
    ('^/login$', view_login),
    ('^/logout$', view_logout),
    ('^/settings$', view_settings),
    ('^/upload$', view_upload),
    ('^/upload-url$', view_upload_url),
    ('^/user-info$', view_user_info),
    ('^/(main\.css|meyer\.css|favicon\.ico)$', view_static),
    ('^/(data/(?:uploads/|users/)?[^/]+)$', view_data),
)
URL_MAPPING = tuple(
    (re.compile(pattern), view) for pattern, view in URL_MAPPING
)


def execute(request):
    session = request.cookies.get('session')
    if session is not None:
        user = load_user(session, hashed=True)
        request.user = user
        request.username_hashed = session

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
