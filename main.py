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
import hmac
import string
import random
import logging
import time

from string import letters
from google.appengine.ext import db

template_dir= os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
    autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)
PASS_RE = re.compile(r"^.{3,20}$")
    
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
    def isAdmin(self):
        if self.user and self.user.user_class=='admin':
            return True
        else:
            return False
class CompanySignup(Handler):
    def get(self):
        if self.isAdmin():
            self.render('add_company.html')
        else:
            self.redirect('/')

    def post(self):
        have_error = False
        self.company.username = self.request.get('username_company')
        self.company.password = self.request.get('password_company')
        self.company.verify = self.request.get('verify_company')
        self.company.email = self.request.get('email_company')

        params = dict(username = self.company.username,
                      email = self.company.email)

        if not valid_username(self.company.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.company.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.company.password != self.company.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.company.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('add_company.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError
class MainHandler(Handler):
    def get(self):
        self.render("main.html")

secret = 'cornel'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


admin = False
class Login(Handler):
    def get(self):
        self.createAdmin()
        self.render('login-form.html')
   
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
       
        u = User.login(username, password)

        if u:
           logging.error(u.user_class) 
           self.login(u)
           if u.name and u.user_class=='admin':
              logging.error('redirectez pe /admin')
              self.redirect('/admin')
        else:
           msg = 'Invalid login'
           self.render('login-form.html', error = msg)
    def createAdmin(self):
        global admin
        if admin:
            return
        u = User.by_class('admin')
       
        if  u:
            return
        else:
            logging.error('exista user admin ' + str(u))
            u = User.register('God', 'herod','admin')
            u.put()
            admin=True
            
        
def users_key(group = 'default'):
    return db.Key.from_path('users', group)
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class AdminHandler(Handler):
    def get(self):
        if self.user and self.user.user_class=='admin':
            self.render('temp.html', username = self.user.name)
        else:
            self.redirect('/')


class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    user_class = db.StringProperty(required=True)
    email = db.StringProperty()
    

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    @classmethod
    def by_class(cls,nume_clasa):
        u = User.all().filter('user_class =', nume_clasa).get()
        return u
    @classmethod
    def register(cls, name, pw, user_class,email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    user_class=user_class,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
    def render(self):
        #self._render_text = self.content.replace('\n', '<br>')
        return render_str("user.html", p = self)
        
        
class TempHandler(Handler):
    def get(self):
        self.render('temp.html')

class NewCompanyHandler(CompanySignup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.company.username)
        if u:
            msg = 'That user already exists.'
            self.render('add_company.html', error_username = msg)
        else:
            u = User.register(self.company.username, self.company.password,'company', self.company.email)
            u.put()

            self.redirect('/admin')

class ListCompaniesHandler(Handler):
    def get(self):
        if self.isAdmin():
            companies = User.all().order('-name')
            self.render('companies_list.html', companies = companies)
        else:
            self.redirect('/')
           
   
class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/')
        
        
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/login',Login),
    ('/admin',AdminHandler),
    ('/admin/temp',TempHandler),
    ('/admin/new',NewCompanyHandler),
    ('/admin/list',ListCompaniesHandler),
    ('/logout',LogoutHandler)
], debug=True)




    






























