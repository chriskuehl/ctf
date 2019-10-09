fuzzy
========

We've recently launched a brand new file-sharing tool called fuzzy. It's kind
of like [fluffy][fluffy], but way more secure.

Fuzzy is a CTF problem originally created for a 2018 hackathon at Yelp. It
consists of a Python web application with several interesting vulnerabilities
to explore and exploit.

In order to simplify the problem, fuzzy was written as a bare WSGI app (not
using any web framework), with a lot of inspiration from `webob`. It's not
really an example of great code, but it was sure fun to write.


## Problems

The solution to each problem is a flag. In each case, the flag will be very
obviously marked once you've found it.

Each problem has a different flag, and they can be completed in any order (they
don't build off of each other).


### Problem 1: Welcome to Fuzzy

Welcome to fuzzy! Why don't you take a look around and maybe create your own
user account?


### Problem 2: Gaining Power

Now you've got that fancy user account. It's just too bad you can't do anything
with it.


### Problem 3: The Secret Backend Server

Microservices, am I right? Good thing our service mesh is fully secured and
only accessible to our own internal services.


## Solutions
### Problem 1: Welcome to Fuzzy

This problem took advantage of a flaw in the webapp where the user was allowed
to control a Python format string:

![welcome message prompt](https://i.fluffy.cc/nQqlSnk8xWsJdj3l7btmnxcJ9qzrrgLf.png)

Allowing untrusted users to control a Python format string is dangerous!

Inside the app, the code looked like this:

```python
welcome_message = request.user['welcome'].format(request=request)
```

Some common (unsuccessful) attempts to solve this part included attempts to
access:

* `request.__dict__`
* `request.__globals__`
* `request.__slots__`

Depending on the actual objects available, any of these could have worked. In
this case, the easiest approach was probably to take advantage of the fact that
functions declared in Python have a `__globals__` attribute, and look at
`request.__init__.__globals__`. This prints a big dictionary of all the globals
on the home page, including one called `SECRET_FLAG_ONE`.


### Problem 2: Gaining Power

The goal of this part was to abuse the file upload feature to perform path
traversal and overwrite your own user JSON definition. You may have noticed a
silly AJAX request happening on every page on fuzzy:

![ajax request](https://i.fluffy.cc/gFMtHszTq36Lb008d5Btx1XmwdqrKjKs.png)

This was meant to clue you in to the fact that user definitions are stored as
JSON blobs on disk, under `/data/users/<userid>.json`. The path for file
uploads is `/data/uploads/<upload>`. Suspicious! (I even added [an artificial
delay][artificial-delay] to try to make the AJAX more obvious :-).)

If you played around with the file upload feature, you'll have noticed it
stores files you upload using the original file name, as opposed to e.g.
[fluffy][fluffy] which gives it a random name. Besides some sneaky validation I
added just to make sure you wouldn't overwrite my Python files, it just takes
the supplied filename verbatim and writes to it, even overwriting existing
files.

One approach is to use curl to overwrite your user JSON blob:

1. Download the blob (the thing from the AJAX request) and change `is_admin` to
   true.
2. Upload a file to replace it:
   ```
   curl -D- -XPOST \
       -H 'Cookie: session=yoursession' \
       -F 'file=@yoursession.json;filename=../users/yoursession.json' \
       http://fuzzy.mycorp.com/upload
   ```

Note that we're using curl here to supply our own "filename" string to send to
the server, totally unrelated to the file name on disk.

After this, refreshing would reveal a "Hello, admin! Here's flag #2:
A1h6gkRaZlXxDekufCmt13Ri7pywR0k4" message.


#### Bonus unintended solution

One participant discovered another solution: upload the session file as usual,
without the path traversal (so that it would be at
`/data/uploads/yoursession.json`), then change your session cookie to
`../uploads/yoursession.json`. Creative!


### Problem 3: The Secret Backend Server

You may have noticed every page on fuzzy returned a weird response header,
`X-From-Secret-Backend`:

![response headers](https://i.fluffy.cc/zWFLCwxqW9f3PcPmf5WCSlqXJzgpMCVF.png)

The goal of this part was to figure out a way to trick fuzzy into returning
content from its own backend server. This is a pretty common and potentially
serious security vulnerability. Imagine if we had a feature in a service that
allowed you to view the contents of a URL: you could potentially just input an
internal service URL and trick the service into talking to any of our internal
backend services!

The approach to this part was to trick the "Upload by URL" feature of fuzzy to
download a page from that secret backend, `http://127.0.0.1:8080/`.

I expected this to be the hardest problem, because I actually added some fairly
significant safeguards to prevent obvious solutions. The upload code did these
checks:

* Blocked private IP networks (`127/8`, `10/8`, etc.).
* Blocked IPv6 addresses.
* Resolved the domain to an IPv4 address and verified it wasn't in any of the
  private IP networks (`127/8`, `10/8`, etc.).
* Made sure protocols were always `http://` or `https://`.
* Rejected any URLs that had "localhost" in them anywhere, because why not?

There are many solutions to this problem. Here are my favorites:

* Trick the upload code by making it follow a redirect to `127.0.0.1:8080`. The
  validation only happens on the original URL; it's happy to follow redirects
  to internal sites. (Several people used this approach.)

  For example, a URL like:
  http://httpbin.org/redirect-to?url=http%3A%2F%2F127.0.0.1%3A8080%2F&status_code=302


* Trick the upload code by using a TOCTOU vulnerability on the DNS check, e.g.
  with a variant of [DNS rebinding][dns-rebinding]. This works by having a
  hostname only sometimes resolve to localhost, so during the validation it
  resolves to a good IP, but during the request it might resolve it to
  localhost. (Nobody actually used this approach, but I think it's so cool.)

  For example, a URL like (using Tavis Ormandy's [rbndr][rbndr]), which
  randomly resolves to either `127.0.0.1` or `216.58.211.110`:
  http://7f000001.d83ad36e.rbndr.us:8080/


* Trick the validation code with a DNS name that has a "good" `A` record, but
  an internal `AAAA` (IPv6) record (of `::1`). The validation happens against
  the `A` record, but the request will prefer the `AAAA` record. (Nobody
  actually used this approach.)

  Example URL:
  http://localtest.ckuehl.me:8080/

* Trick the validation code using a DNS name with two `A` records, one for
  `127.0.0.1`, and one for something else. (Nobody actually used this
  approach.)


* Use `http://0.0.0.0:8080/` (unfortunately, this was not intentionally
  possible, but several people found out it worked; this made the problem quite
  a bit easier than I wanted it to be, but at least I learned something new!)

Once using one of the URLs above, you'd hit an nginx backend (the "secret"
backend) listening on port 8080 which just returned the flag:

```nginx
server {
    listen       127.0.0.1:8080;
    listen       [::1]:8080;
    location / {
        return 200 'Hello! Flag #3 is: GdWKDHlaoWuLrbxJw5kKIxFmGRNHgCrg\n';
    }
}
```

In the real world, of course, you'd be hitting some real backend server and
potentially be able to get access to sensitive data.


[fluffy]: https://fluffy.cc/
[artificial-delay]: https://github.com/chriskuehl/ctf/blob/498a03ebb51ed93b76c88b40c93351a211ab2766/fuzzy/templates/base.jinja2#L54
[dns-rebinding]: https://en.wikipedia.org/wiki/DNS_rebinding
[rbndr]: https://github.com/taviso/rbndr
