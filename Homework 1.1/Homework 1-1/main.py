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

# Udacity Web Development Problem Set 2: Rot 13

import webapp2
import cgi

form="""
<form method="post">
<b>Enter some text to Rot13:</b>
<br>

<textarea name="text" rows="4" cols="50">
%(text)s
</textarea>

<br>

<input type="submit">
</form>
"""

class MainHandler(webapp2.RequestHandler):
    def write_form(self, text=""):
        self.response.out.write(form % {"text": text})

    def rot13(self, text):
        if text:
            str=""
            for i in text:
                if i.isalpha:
                    temp = ord(i)
                    if(temp >= 97 and temp <= 109) or (65 <= temp <= 77):
                        temp += 13
                        str += chr(temp)
                    elif (temp >= 110 and temp <= 122) or  (temp >= 78 and temp <= 90):
                        temp -= 13
                        str += chr(temp)
                    else:
                        str += i
        return str

    def escape_html(self, text):
        return cgi.escape(text, quote=True)

    def get(self):
        self.write_form()

    def post(self):
        rot13_text = self.request.get('text')

        if rot13_text:
            rot13_text = self.rot13(rot13_text)
            rot13_text = self.escape_html(rot13_text)
            self.write_form(rot13_text)
        else:
            self.response.out.write("Please enter some text")

app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
