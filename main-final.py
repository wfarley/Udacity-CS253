#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import re
import os
import jinja2
import hashlib
import random
import string
import hmac

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


SECRET = 'ASecKey'

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_username(username):
    return USERNAME_RE.match(username)


def valid_password(password):
    return PASSWORD_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email)

#-------------------------------------------------


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        template = jinja_env.get_template(template)
        return template.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


#-------------------------------------------------

class WikiUser(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class WikiEntry(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

#-------------------------------------------------


def make_secure_val(s):
    return '%s|%s' % (s, hmac.new(SECRET, s).hexdigest())


# takes string of the format s|HASH and returns s if valid
def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt():
        return ''.join(random.choice(string.letters) for x in xrange(5))


def make_password_hash(username, password, salt=""):
        if not salt:
            salt = make_salt()
        h = hashlib.sha256(username + password + salt).hexdigest()
        return '%s|%s' % (h, salt)


class SignupHandler(Handler):
    def render_form(self, user="", email="", username_error="", password_error="", verify_error="", email_error=""):
        self.render("signup.html", user=user, email=email, username_error=username_error, password_error=password_error, verify_error=verify_error, email_error=email_error)

    def get(self):
        self.render_form()

    def set_cookie(self, cookie_name, cookie_value):
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (cookie_name, cookie_value))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        username_valid = valid_username(username)
        password_valid = valid_password(password)
        email_valid = valid_email(email)
        if email == "":
            email_valid = True

        err_user = ""
        err_pass = ""
        err_verify = ""
        err_email = ""
        if not username_valid:
            err_user = "That's not a valid username"
        if not password_valid:
            err_pass = "That wasn't a valid password"
        if password != verify:
            err_verify = "Your passwords didn't match"
        if not email_valid:
            err_email = "That's not a valid email"

        if username_valid and password_valid and email_valid and password == verify:
            # check if user already exists
            users = db.GqlQuery("SELECT * FROM WikiUser WHERE username = :username", username=username)

            if users.count() > 0:
                self.render_form(username, email, "That user already exists.")
            else:
                # add user to db
                new_user = WikiUser(username=username, password_hash=make_password_hash(username, password), email=email)
                user_key = new_user.put()

                # set cookie
                user_id = user_key.id()
                self.set_cookie('user-id', make_secure_val(str(user_id)))

                # redirect to welcome page
                self.redirect("/")
        else:
            self.render_form(username, email, err_user, err_pass, err_verify, err_email)


class LoginHandler(Handler):
    def render_form(self, error=""):
        self.render("login.html", error=error)

    def set_cookie(self, cookie_name, cookie_value):
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (cookie_name, cookie_value))

    def get(self):
        self.render_form()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        error = False

        if username and password:
            users_query = db.GqlQuery("SELECT * FROM WikiUser WHERE username = :username", username=username)
            user = users_query.get()
            if user:
                # create hash value for the entered password
                salt = user.password_hash.split('|')[1]
                h = make_password_hash(username, password, salt)
                if h == user.password_hash:
                    self.set_cookie('user-id', make_secure_val(str(user.key().id())))
                    self.redirect("/")
                else:
                    error = True
            else:
                error = True
        else:
            error = True

        if error:
            self.render_form("Invalid login")


class LogoutHandler(Handler):
    def set_cookie(self, cookie_name, cookie_value):
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (cookie_name, cookie_value))

    def get(self):
        # "delete" cookie - set value to empty
        self.set_cookie('user-id', "")
        self.redirect(self.request.headers['Referer'])      # Redirect to the previous page

#-------------------------------------------------


def get_username_from_cookie(user_id_val):
    user_id = check_secure_val(user_id_val)

    if user_id:
        user = WikiUser.get_by_id(int(user_id))
        if user:
            return user.username

    return ""


class WikiPageHandler(Handler):
    def render_page(self, username="", subject="/", content=""):
        self.render("wikiview.html", username=username, subject=subject, content=content)

    def get(self, subject):
        if subject is None:
            subject = "/"

        username = get_username_from_cookie(self.request.cookies.get('user-id', '0'))

        content = memcache.get(subject)
        if content is None:
            entry_q = db.GqlQuery("SELECT * FROM WikiEntry WHERE subject=:1", subject)
            entry = entry_q.get()
            if entry:
                content = entry.content

                memcache.set(subject, content)
            else:
                self.redirect("/_edit" + subject)

        self.render_page(username, subject, content)


class EditPageHandler(Handler):
    def render_page(self, username="", subject="/", content=""):
        self.render("wikiedit.html", username=username, subject=subject, content=content)

    def get(self, subject):
        username = get_username_from_cookie(self.request.cookies.get('user-id', '0'))

        if username == "":
            self.redirect("/login")
        else:
            content = memcache.get(subject)
            if content is None:
                content = ""

                entry_q = db.GqlQuery("SELECT * FROM WikiEntry WHERE subject=:1", subject)
                entry = entry_q.get()
                if entry:
                    content = entry.content

                    memcache.set(subject, content)

            self.render_page(username, subject, content)

    def post(self, subject):
        username = get_username_from_cookie(self.request.cookies.get('user-id', '0'))

        if username == "":
            self.redirect("/login")
        else:
            content = self.request.get('content')

            if content:
                memcache.set(subject, content)

                entry = WikiEntry(subject=subject, content=content)
                entry.put()

                self.redirect(subject)


#-------------------------------------------------

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/_edit' + PAGE_RE, EditPageHandler),
                               (PAGE_RE, WikiPageHandler),
                               ],
                              debug=True)
