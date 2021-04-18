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
import cgi
import hashlib
import random
import string
import jinja2
import os
from google.appengine.ext import db


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

secret = "al.121jfnloepap^2d$^.76#1@80"


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASSWORD_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email)


def valid_verify(verify, password):
    if verify == password:
        return True
    else:
        return False


def make_salt():
    # Your code here
    salt_string = ""
    for x in range(5):
        salt_string += random.choice(string.ascii_letters)

    return salt_string


def make_cookie_hash(s):
    # Your code here

    hashed_cookie = hashlib.sha256(s + secret).hexdigest()

    return "%s|%s" % (s, hashed_cookie)


def valid_cookie(s, h):
    hashed_cookie = make_cookie_hash(s)

    if h == hashed_cookie:
        return s
    else:
        return None


def make_pw_hash(username, pw, salt=None):
    #Your code here
    if salt is None:
        salt = make_salt()

    hashed_pw = hashlib.sha256(username + pw + salt).hexdigest()

    return "%s,%s,%s" % (hashed_pw, username, salt)


def valid_pw(username, pw, h):
    salt = h.split(",")[2]
    hashed_pw = make_pw_hash(username, pw)

    if h == hashed_pw:
        return username
    else:
        return None


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class UserAccounts:
    user_accounts = []


class User(db.Model):
    user_name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.EmailProperty()
    created = db.DateTimeProperty(auto_now_add = True)


class MainHandler(Handler):
    def write_form(self, user_error="", pass_error="", verify_error="", email_error="", username="", email=""):
        self.render("form.html", user_error=cgi.escape(user_error),
                                        pass_error=pass_error,
                                        verify_error=verify_error,
                                        email_error=email_error,
                                        username=cgi.escape(username),
                                        email=cgi.escape(email))

    def get(self):
        self.render("form.html")

    def post(self):
        global user_name
        global accounts
        accounts = UserAccounts()

        global user_id_cookie_val
        user_id_cookie_val = self.request.cookies.get('user_id', '2000')
        user_id = 2000

        user_name = self.request.get('username')
        user_password = self.request.get('password')
        user_email = self.request.get('email')
        user_verify = self.request.get('verify')

        name = valid_username(user_name)
        password = valid_password(user_password)
        email = valid_email(user_email)
        verify = valid_verify(user_verify, user_password)
        account_exist = 0

        user_error = ""
        pass_error = ""
        verify_error = ""
        email_error = ""

        if not name:
            user_error = "That's not a valid username."
        elif len(accounts.user_accounts) > 0:
                for x in accounts.user_accounts:
                    if user_name == x:
                        user_error = "That username already exists."
                        account_exist = 1

        if not password:
            pass_error = "That wasn't a valid password."

        if password and not verify:
            verify_error = "Your passwords didn't match."

        if len(user_email) > 0 and not email:
            email_error = "That's not a valid email."

        if (not (name and password and verify)) or (account_exist == 1) or (user_email and not email):
            self.write_form(user_error, pass_error, verify_error, email_error, user_name, user_email)
        else:
            if user_id_cookie_val:
                id_str = user_id_cookie_val.split("|")[0]
                cookie_val = valid_cookie(id_str, user_id_cookie_val)

                if cookie_val:
                    user_id = int(cookie_val)

            user_id += 1

            accounts.user_accounts.append(user_name)

            new_cookie_val = make_cookie_hash(str(user_id))

            self.response.headers.add_header('set-cookie', 'user_id=%s' % new_cookie_val)

            password_hash = make_pw_hash(user_name, user_password)

            if len(user_email) > 0 and email:
                a = User(user_name=user_name, pw_hash=password_hash, email=user_email)
            else:
                a = User(user_name=user_name, pw_hash=password_hash)
            a.put()

            self.redirect("/welcome")


class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        global user_id_cookie_val
        user_id_cookie_val = self.request.cookies.get('user_id')
        id_str = user_id_cookie_val.split("|")[0]

        self.response.out.write("Welcome %s" % user_name)

        if user_id_cookie_val:
            cookie_val = valid_cookie(id_str, user_id_cookie_val)

            if cookie_val is None:
                self.redirect("/signup")


class Login(Handler):
    def render_login(self, login_error=""):
        self.render("login.html", login_error=login_error)

    def get(self):
        self.render("login.html")

    def post(self):
        users = db.GqlQuery("SELECT * FROM User ORDER BY created DESC")

        user_name_login = self.request.get('username')
        user_password_login = self.request.get('password')
        user_id_login = 2001
        login_found = 0

        for user in users:
            if user.user_name == user_name_login:
                salt = user.pw_hash.split(",")[2]
                user_login_hash = make_pw_hash(user_name_login, user_password_login, salt)
                if user.pw_hash == user_login_hash:
                    global user_name
                    user_name = user_name_login
                    global user_id_cookie_val
                    user_id_cookie_val = self.request.cookies.get('user_id', str(user_id_login))
                    self.redirect("/welcome")
                    login_found = 1
                else:
                    user_id_login += 1

        if login_found == 0:
            login_error = "Invalid login"
            self.render_login(login_error)


class Logout(Handler):
    def get(self):
        # self.response.headers.add_header('set-cookie', 'user_id=', Path='/')
        # self.redirect('/signup')
        usercookie = 'user_id='
        usercookie = usercookie.encode('utf-8')
        self.response.headers.add_header('Set-Cookie', usercookie, Path='/')
        redirect_url = "/signup"

        self.redirect(redirect_url)


app = webapp2.WSGIApplication([
    ('/signup', MainHandler), ('/welcome', ThanksHandler), ('/login', Login), ('/logout', Logout)], debug=True)
