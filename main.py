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
import cgi
import re
import os
import jinja2
import hashlib
import random
import string
import hmac
import json
import time

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


SECRET = 'ASecKey'

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

###HW6-1
#last_query_time = 0
###
###HW6-2
last_query_times = {}
###

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

#HW4
class BlogUser(db.Model):
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)


#HW3
class BlogEntry(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)


#-------------------------------------------------

class HW6FlushHandler(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')


#-------------------------------------------------

class HW5BlogPermalinkJSONHandler(Handler):
    def get(self, post_id):
        self.response.headers['Content-Type'] = "application/json"
        
        post = BlogEntry.get_by_id(int(post_id))
        if post:
            post_obj = {}
            post_obj["content"] = post.content
            post_obj["subject"] = post.subject
            self.write(json.dumps(post_obj))
        else:
            self.write("This entry does not exist!")


class HW5BlogJSONHandler(Handler):
    def get(self):
        self.response.headers['Content-Type'] = "application/json"

        posts_list = []
        
        posts = db.GqlQuery("SELECT * from BlogEntry ORDER BY created DESC LIMIT 10")

        for post in posts:
            post_obj = {}
            post_obj["content"] = post.content
            post_obj["subject"] = post.subject
            posts_list.append(post_obj)

        self.write(json.dumps(posts_list))

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

class HW4SignupHandler(Handler):
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
            users = db.GqlQuery("SELECT * FROM BlogUser WHERE username = :username", username=username)
            
            if users.count() > 0:
                self.render_form(username, email, "That user already exists.")
            else:
                # add user to db
                new_user = BlogUser(username = username, password_hash = make_password_hash(username, password), email = email)
                user_key = new_user.put()

                # set cookie
                user_id = user_key.id()
                self.set_cookie('user-id', make_secure_val(str(user_id)))

                # redirect to welcome page
                self.redirect("/blog/welcome")   #/hw4/welcome
        else:
            self.render_form(username, email, err_user, err_pass, err_verify, err_email)


class HW4WelcomeHandler(Handler):
    def render_page(self, username):
        self.render("welcome.html", username=username)

    def get(self):
        # get cookie
        user_id_val = self.request.cookies.get('user-id',0)
        # validate cookie
        user_id = check_secure_val(user_id_val)
        # if valid, render welcome with username
        if user_id:
            user = BlogUser.get_by_id(int(user_id))
            if user:
                self.render_page(user.username)
        else:
            #if not valid, redirect to signup form
            self.redirect('/blog/signup')    #/hw4/signup


class HW4LoginHandler(Handler):
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
            users_query = db.GqlQuery("SELECT * FROM BlogUser WHERE username = :username", username = username)
            user = users_query.get()
            if user:                
                # create hash value for the entered password
                salt = user.password_hash.split('|')[1]
                h = make_password_hash(username, password, salt)
                if h == user.password_hash:
                    self.set_cookie('user-id', make_secure_val(str(user.key().id())))
                    self.redirect("/blog/welcome")   #/hw4/welcome
                else:
                    error = True
            else:
                error = True
        else:
            error = True
            
        if error:
            self.render_form("Invalid login")


class HW4LogoutHandler(Handler):
    def set_cookie(self, cookie_name, cookie_value):
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (cookie_name, cookie_value))
        
    def get(self):
        # "delete" cookie - set value to empty
        self.set_cookie('user-id', "")
        self.redirect("/blog/signup")    #/hw4/signup


#-------------------------------------------------

class HW3BlogNewPostHandler(Handler):
    def render_front(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)
        
    def get(self):
        self.render_front()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            post = BlogEntry(subject = subject, content = content)
            postkey = post.put()

            memcache.delete('front_posts')  ###HW6-1

#            self.redirect("/hw3blog/%d" %postkey.id())
            self.redirect("/blog/%d" %postkey.id())
        else:
            error = "You need both a subject and content"
            self.render_front(subject, content, error)


class HW3BlogHandler(Handler):
    def get(self):
        global last_query_times

        posts = memcache.get('front_posts') ###HW6-1
        if posts is None:   ###HW6-1
            posts = db.GqlQuery("SELECT * from BlogEntry ORDER BY created DESC LIMIT 10")

            posts = list(posts) ###HW6-1

            last_query_times['front_posts'] = time.time()   ###HW6-1

            memcache.set('front_posts', posts)  ###HW6-1

        
        self.render("blogfront.html", posts=posts, querytime=int(time.time() - last_query_times['front_posts']))


class HW3BlogPermalinkHandler(Handler):
    def get(self, post_id):
        post_found = True  ###HW6-2

        key = 'post' + post_id
        
        posts = memcache.get(key)  ###HW6-2
        if posts is None:   ###HW6-2
            post = BlogEntry.get_by_id(int(post_id))
            if post:
                posts = []
                posts.append(post)

                last_query_times[key] = time.time()    ###HW6-2
                memcache.set(key, posts)    ###HW6-2
                
            else:
                post_found = False    ###HW6-2
                

        ###HW6-2
        if post_found == True:
            self.render("blogfront.html", posts = posts, querytime=int(time.time() - last_query_times[key]))
        else:
            self.write("This entry does not exist!")

#-------------------------------------------------

hw22Form="""
<h1>Signup</h1>
<form method="post">
    <label>Username:
        <input name="username" value="%(user)s">
    </label>
    <label>%(username_error)s</label>
    <br>
    <label>Password:
        <input type="password" name="password">
    </label>
    <label>%(password_error)s</label>
    <br>
    <label>Verify Password:
        <input type="password" name="verify">
    </label>
    <label>%(verify_error)s</label>
    <br>
    <label> Email (optional):
        <input name="email" value="%(email)s">
    </label>
    <label>%(email_error)s</label>
    <br>
    <input type="submit">
</form>
"""

class HW22Handler(webapp2.RequestHandler):
    def write_form(self, user="", email="", username_error="", password_error="", verify_error="", email_error=""):
        self.response.out.write(hw22Form % {"user": user, "email": email, "username_error": username_error, "password_error": password_error, "verify_error": verify_error, "email_error": email_error})

    def get(self):
        self.write_form()

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        username_valid = valid_username(user_username)
        password_valid = valid_password(user_password)
        email_valid = valid_email(user_email)
        if user_email == "":
            email_valid = True

        esc_username = cgi.escape(user_username, quote=True)
        esc_email = cgi.escape(user_email, quote=True)

        err_user = ""
        err_pass = ""
        err_verify = ""
        err_email = ""
        if not username_valid:
            err_user = "That's not a valid username"
        if not password_valid:
            err_pass = "That wasn't a valid password"
        if user_password != user_verify:
            err_verify = "Your passwords didn't match"
        if not email_valid:
            err_email = "That's not a valid email"

        if username_valid and password_valid and email_valid and user_password == user_verify:
            self.redirect("/hw22/validsignup?username=%s" %esc_username)
        else:
            self.write_form(esc_username, esc_email, err_user, err_pass, err_verify, err_email)

class HW22ValidHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get("username")
        self.response.out.write("Welcome, %s" %username)

#-------------------------------------------------

form="""
Enter some text to ROT13:
<form method="post">
    <textarea name="text" style="height: 100px; width: 400px;">
    %(data)s
    </textarea>
    <br>
    <input type="submit">
</form>
"""

#Homework 2.1
class MainHandler(webapp2.RequestHandler):
    def write_form(self, text=""):
        self.response.out.write(form % {"data": text})

    def do_rot13(self, text):
#        i = 0
#        while i < len(text):
#            if text and text[i].isalpha():
#                text[i] = chr(ord(text[i]) + 13))
#            i = i + 1

        return text.encode("rot13")

    def get(self):
        self.write_form()
        
    def post(self):
        #self.write_form()
        user_text = self.request.get('text')

        new_text = self.do_rot13(user_text)

        esc_text = cgi.escape(new_text, quote = True)
        
        self.write_form(esc_text)

#-------------------------------------------------

app = webapp2.WSGIApplication([('/', MainHandler),
                               ('/hw22', HW22Handler),
                               ('/hw22/validsignup', HW22ValidHandler),
#                               ('/hw3blog', HW3BlogHandler),
                               ('/blog', HW3BlogHandler),
#                               ('/hw3blog/newpost', HW3BlogNewPostHandler),
                               ('/blog/newpost', HW3BlogNewPostHandler),
#                               (r'/hw3blog/(\d+)', HW3BlogPermalinkHandler),
                               (r'/blog/(\d+)', HW3BlogPermalinkHandler),
#                               ('/hw4/signup', HW4SignupHandler),
                               ('/blog/signup', HW4SignupHandler),
#                               ('/hw4/welcome', HW4WelcomeHandler),
                               ('/blog/welcome', HW4WelcomeHandler),
#                               ('/hw4/login', HW4LoginHandler),
                               ('/blog/login', HW4LoginHandler),
#                               ('/hw4/logout', HW4LogoutHandler),
                               ('/blog/logout', HW4LogoutHandler),
#                               ('/hw3blog/?.json', HW5BlogJSONHandler),
                               ('/blog/?.json', HW5BlogJSONHandler),
#                               (r'/hw3blog/(\d+).json', HW5BlogPermalinkJSONHandler)],
                               (r'/blog/(\d+).json', HW5BlogPermalinkJSONHandler),
                               ('/blog/flush', HW6FlushHandler)],
                              debug=True)
