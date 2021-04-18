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

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

form="""
    <form method="post">
    <h2>Signup</h2>
    <br>
    <label>
    Username
    <input name="username" value="%(username)s" type="text">
    <b style="color: red">%(user_error)s</b>
    </label>
    <br>
    <label>
    Password
    <input name="password" type="password">
    <b style="color: red">%(pass_error)s</b>
    </label>
    <br>
    <label>
    Verify Password
    <input name="verify" type="password">
    <b style="color: red">%(verify_error)s</b>
    </label>
    <br>
    <label>
    Email (Optional)
    <input name="email" value="%(email)s" type="text">
    <b style="color: red">%(email_error)s</b>
    </label>
    <br>
    <input type="submit">
    </form>
"""


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


class MainHandler(webapp2.RequestHandler):
    def write_form(self, user_error="", pass_error="", verify_error="", email_error="", username="", email=""):
        self.response.out.write(form % {"user_error": cgi.escape(user_error),
                                        "pass_error": pass_error,
                                        "verify_error": verify_error,
                                        "email_error": email_error,
                                        "username": cgi.escape(username),
                                        "email": cgi.escape(email)})

    def get(self):
        self.write_form()

    def post(self):
        global user_name
        user_name = self.request.get('username')
        user_password = self.request.get('password')
        user_email = self.request.get('email')
        user_verify = self.request.get('verify')

        name = valid_username(user_name)
        password = valid_password(user_password)
        email = valid_email(user_email)
        verify = valid_verify(user_verify, user_password)

        user_error = ""
        pass_error = ""
        verify_error = ""
        email_error = ""

        if not name:
            user_error = "That's not a valid username."

        if not password:
            pass_error = "That wasn't a valid password."

        if password and not verify:
            verify_error = "Your passwords didn't match."

        if len(user_email) > 0 and not email:
            email_error = "That's not a valid email."

        if (not (name and password and verify)) or (user_email and not email):
            self.write_form(user_error, pass_error, verify_error, email_error, user_name, user_email)
        else:
            self.redirect("/thanks")


class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Welcome %s" % user_name)

app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/thanks', ThanksHandler)], debug=True)
