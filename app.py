#Application Security
#Andrew Vittetoe
#05OCT2019
#Assignment #3


# importing modules
import os
from os import environ
import sqlite3
import time
import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask import Flask, render_template, request, flash, url_for, session, redirect
from flask_session import Session
from flask_wtf import FlaskForm
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from spellchecker import SpellChecker
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, ForeignKey, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from flask_sqlalchemy_session import flask_scoped_session
from getpass import getpass
from hashlib import sha256 as SHA256
from hashlib import sha512 as SHA512
from secrets import token_hex
from datetime import datetime

# Initialize Application and global configs --------------------------------------------------------------------------------------------------------

# -- App Settings --
# initializing a variable of Flask
app = Flask(__name__)

# -- DB settings --
# Declare base as per Professor's example from webinar
BASE = declarative_base()
DBFILE = "assignment_3.db"

engine = create_engine(f'sqlite:///{DBFILE}')
BASE.metadata.bind = engine


# -- Global Variable Settings --
# Initialize Variables
logged_in = False
user_logged_in = ""
queryid = 0
user_search_id = 0

# -- Security Settings --
# Set secure cookies
app.session_cookie_secure = True
app.remember_cookie_secure = True
# Set HTTP Only
app.session_cookie_httponly = True
app.remember_cookie_httponly = True
# Lifetime set to 1 minute
app.permanent_session_lifetime = 60
app.session_permanent = False
# Set secret key
app.secret_key = os.environ.get('SECRET_KEY') or '6\xe9\xda\xead\x81\xf7\x8d\xbbH\x87\xe8m\xdd3%'

# DB Model ---------------------------------------------------------------------------------------------------------------------------------------
class User(BASE):
    __tablename__ = 'users'
    user_ID = Column(Integer, primary_key=True, autoincrement=True)
    uname = Column(String(25), nullable=False, unique=True)
    pword = Column(String(64), nullable=False)
    ID_2fa = Column(String(64), nullable=False)
    pw_salt = Column(String(16), nullable=False)
    mfa_salt = Column(String(16), nullable=False)
    #log_ID = Column(Integer, ForeignKey('log_records.log_ID'))
    #query_ID= Column(Integer, ForeignKey('query_records.query_ID'))
    child_logs = relationship('Log_Record')
    child_queries = relationship('Query_Record')

    def __init__(self, uname, pword, ID_2fa, pw_salt, mfa_salt):  
        #self.user_ID = user_ID
        self.uname = uname
        self.pword = pword
        self.ID_2fa = ID_2fa
        self.pw_salt = pw_salt
        self.mfa_salt = mfa_salt

class Log_Record(BASE):
    __tablename__ = 'log_records'
    log_ID =  Column(Integer, primary_key=True, autoincrement=True)
    action_type = Column(String(8), nullable=False)
    action_time = Column(DateTime, default = datetime.now(), nullable=False)
    user_ID = Column(Integer, ForeignKey('users.user_ID'), nullable=False)

    def __init__(self, user_ID, action_type):  
        #self.log_ID = user_ID
        self.user_ID = user_ID
        self.action_type = action_type
        #self.action_time = action_time
        #self.user = user

class Query_Record(BASE):
    __tablename__ = 'query_records'
    query_ID =  Column(Integer, primary_key=True, autoincrement=True)
    querytext = Column(String(500), nullable=False)
    queryresults = Column(String(500), nullable=False)
    action_time = Column(DateTime, default = datetime.now(), nullable=False)
    username = Column(Integer, ForeignKey('users.user_ID'), nullable=False)

    def __init__(self, user_ID, text_submitted, results_received):  
        #self.query_ID = query_ID
        self.user_ID = user_ID
        self.text_submitted = text_submitted
        self.results_received = results_received
        #self.action_time = action_time
        #self.user = user

# Clean-up prior work
# REMOVE BEFORE SUBMITTING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! <-----Important
BASE.metadata.drop_all(engine)

# Create DB again
BASE.metadata.create_all(engine)
#DBSessionMaker = sessionmaker(bind=engine, autoflush=False, autocommit=False)
DBSessionMaker = sessionmaker(bind=engine)

session = DBSessionMaker()

# Create Admin
admin_uname = "admin"
#admin_pword = "Administrator@1"
#admin_ID_2fa = "12345678901"
admin_pword = "admin"
admin_ID_2fa = "admin"
pw_hasher = SHA512()
mfa_hasher = SHA256()
# SALT PW
pw_hasher.update(admin_pword.encode('utf-8'))
salt_pw_value = token_hex(nbytes=16)
pw_hasher.update(salt_pw_value.encode('utf-8'))
pword_hexed = pw_hasher.hexdigest()
# SALT MFA
mfa_hasher.update(admin_ID_2fa.encode('utf-8'))
salt_mfa_value = token_hex(nbytes=16)
mfa_hasher.update(salt_mfa_value.encode('utf-8'))
mfa_hexed = mfa_hasher.hexdigest()
# Create User class with admin info
admin_user = User(uname=admin_uname, pword=pword_hexed, pw_salt=salt_pw_value, ID_2fa=mfa_hexed, mfa_salt=salt_mfa_value)

# Add admin user to DB
session.add(admin_user)
session.commit()

# Get just added admin's user_ID
just_added_admin = session.query(User).filter(User.uname == "admin").first()

# REMOVE BEFORE SUBMITTING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! <--------IMPORTANT
print("ID: ", just_added_admin.user_ID, " uname: ", admin_user.uname, " pword: ", admin_user.pword, " MFA: ", admin_user.ID_2fa, " pw_salt: ", admin_user.pw_salt, " mfa_salt ", admin_user.mfa_salt)


user_data = session.query(User).all()
for i in user_data:
    print("admin create: ", i.user_ID, i.uname)

session.close()


# Routes -----------------------------------------------------------------------------------------------------------------------------------------
# Home page / register
@app.route('/', methods=['POST','GET'])
@app.route("/home", methods=['POST','GET'])
@app.route("/register", methods=['POST','GET'])
def register():
        
    form = RegisterForm()
    success = ""
  
    pw_hasher = SHA512()
    mfa_hasher = SHA256()

    # If submitted and validated, save info but do not login
    if form.validate_on_submit():

        global DBSessionMaker
        session = DBSessionMaker()

        # Pull info from form
        uname = form.uname.data
        ID_2fa = form.ID_2fa.data
        pword = form.pword.data

        # Check if already exists
        existing_user = session.query(User).filter(User.uname == uname).first()

        if not existing_user:

            # SALT PW
            pw_hasher.update(pword.encode('utf-8'))
            salt_pw_value = token_hex(nbytes=16)
            pw_hasher.update(salt_pw_value.encode('utf-8'))
            pword_hexed = pw_hasher.hexdigest()
            # SALT MFA
            mfa_hasher.update(ID_2fa.encode('utf-8'))
            salt_mfa_value = token_hex(nbytes=16)
            mfa_hasher.update(salt_mfa_value.encode('utf-8'))
            mfa_hexed = mfa_hasher.hexdigest()

            # Create User class with user info
            new_user = User(uname=uname, pword=pword_hexed, ID_2fa=mfa_hexed, pw_salt=salt_pw_value, mfa_salt=salt_mfa_value)
            
            # Add new user and log to DB
            session.add(new_user)
            session.commit()

            # Get just added user's user_ID
            just_added_user = session.query(User).filter(User.uname == uname).first()

            # Create log record of registration
            new_log = Log_Record(user_ID=just_added_user.user_ID, action_type="register")
            session.add(new_log)
            session.commit()

            # REMOVE BEFORE SUBMITTING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! <--------IMPORTANT
            print("ID: ", new_user.user_ID, " uname: ", new_user.uname, " pword: ", new_user.pword, " MFA: ", new_user.ID_2fa, " pw_salt: ", new_user.pw_salt, " mfa_salt ", new_user.mfa_salt)
            print("log: ", new_log.log_ID, " user_ID: ", new_log.user_ID, " action: ", new_log.action_type, " time: ", new_log.action_time)

            user_data = session.query(User).all()
            for i in user_data:
                print("register: ", i.user_ID, i.uname)

            # Return success
            success = "succcess"

        else:
            success = "failure - user already exists"
        
        session.close()

    # Doesn't pass validation
    else:
        success = "failure"

    return render_template("register.html", title="Register", form=form, register=True, success=success, logged_in=logged_in, user_logged_in=user_logged_in)


# Login page
@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    result = ""
    unameSuccess = "false"
    pwordSuccess = "false"
    ID_2faSuccess = "false"
    pw_hasher = SHA512()
    mfa_hasher = SHA256()

    if form.validate_on_submit():

        global DBSessionMaker
        session = DBSessionMaker()

        user_data = session.query(User).all()
        for i in user_data:
            print("login: ", i.user_ID, i.uname)

        uname = form.uname.data
        ID_2fa = form.ID_2fa.data
        pword = form.pword.data

        # Retrieve user info from DB
        user_record = session.query(User).filter(User.uname == uname).first()
        pw_salt = user_record.pw_salt
        mfa_salt = user_record.mfa_salt

        # Add password and pw salt to hasher
        pw_hasher.update(pword.encode('utf-8'))
        pw_hasher.update(pw_salt.encode('utf-8'))
        password_hash = pw_hasher.hexdigest()

        # Add mfa and mfa salt to hasher
        mfa_hasher.update(ID_2fa.encode('utf-8'))
        mfa_hasher.update(mfa_salt.encode('utf-8'))
        mfa_hash = mfa_hasher.hexdigest()

        # Confirm that the credentials are correct
        if(password_hash == user_record.pword):
            # Return success on uname & pword
            unameSuccess = "true"
            pwordSuccess = "true"

            # Confirm MFA is correct
            if(mfa_hash == user_record.ID_2fa):
                # Return success on uname & pword
                ID_2faSuccess = "true"


        if unameSuccess == "true" and pwordSuccess == "true" and ID_2faSuccess == "true":
            global logged_in
            global user_logged_in
            logged_in = True
            user_logged_in = user_record.user_ID

            # Create log record of login
            new_log = Log_Record(user_ID=user_record.user_ID, action_type="login")

            # Add log record to DB
            session.add(new_log)
            session.commit()

            result = "Success"

            # REMOVE BEFORE SUBMITTING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! <--------IMPORTANT
            just_added_log = session.query(Log_Record).filter(Log_Record.user_ID == user_record.user_ID).all()
            for j in just_added_log:
                print("log: ", j.log_ID, " user_ID: ", j.user_ID, " action: ", j.action_type, " time: ", j.action_time)

        elif unameSuccess == "false":
            result = "incorrect"
        elif pwordSuccess == "false":
            result = "incorrect"
        elif ID_2faSuccess == "false":
            result = "Two-factor failure"
        
        session.close()
    
    # Doesn't pass validation
    else:
        result = "failure"
    
    return render_template("login.html", title="Login", form=form, login=True, result=result, logged_in=logged_in, user_logged_in=user_logged_in)

# Logout page (not really a page but a redirect that also clears sessiona and adds a log record)
@app.route("/logout")
def logout():
    global logged_in
    global user_logged_in

    # If not logged in, send to login page and stop
    if not logged_in:
        return redirect(url_for('login'))
    
    # Create log record of login
    log_record = Log_Record(user_id=user_logged_in, action_type="logout", logged_in=logged_in)

    # REMOVE BEFORE SUBMITTING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! <--------IMPORTANT
    print(log_record)

    # Add log record to DB
    session.add(log_record)
    session.commit()

    # Clear session state
    logged_in = False
    user_logged_in = ""
    
    # Redirect to home/register page
    return redirect(url_for('register'))

# Spell_Check page
@app.route("/spell_check", methods=['GET','POST'])
def spell_check():

    global user_logged_in
    global logged_in

    # If not logged in, send to login page and stop
    if not logged_in:
        return redirect(url_for('login'))

    form = SpellCheckForm()
    textout = []
    misspelled = []
    uname = session.get('user_ID')
    
    # See if text is validated
    if form.validate_on_submit():
        spell = SpellChecker()
        inputtext = form.inputtext.data

        # Parse text
        words = inputtext.split()

        # Find out if words are misspelled
        for word in words:
            if word in spell:
                textout.append(word)
            else:
                misspelled.append(word)
    
        # Create log record of query
        query_record = Query_Record(username=uname, querytext=inputtext, queryresults=misspelled)

        # REMOVE BEFORE SUBMITTING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! <--------IMPORTANT
        print(query_record)

        # Add query record to DB
        session.add(query_record)
        session.commit()

    return render_template("spell_check.html", title="Spell Check", form=form, spell_check=True, textout=textout, misspelled=misspelled, logged_in=logged_in, user_logged_in=user_logged_in)


# History page
@app.route("/history", methods=['GET','POST'])
def history():

    form = QueryForm()
    global user_logged_in
    global logged_in

    # If not logged in, send to login page and stop
    if not logged_in:
        return redirect(url_for('login'))
    
    # Assume we want the data for the user logged in
    userquery = user_logged_in
    queries = session.query(User).filter(User.user_ID == userquery).all()
    numqueries = queries = session.query(User).filter(User.user_ID == userquery).count()

    # If form submit
    if form.validate_on_submit():
            # If admin user search was pressed, override query
            if form.userquery_submit.data:
                userquery = form.userquery.data
                queries = session.query(User).filter(User.user_ID == userquery).all()
                numqueries = queries = session.query(User).filter(User.user_ID == userquery).count()
            # Else it was the queryreview button presssed
            else:
                queryid = form.query_review.data


    return render_template("history.html", title="History", history=True, form=form, queries=queries, numqueries=numqueries, userquery=userquery, logged_in=logged_in, user_logged_in=user_logged_in)

# Query Review page
@app.route("/query", methods=['GET','POST'])
def query():

    global user_logged_in
    global logged_in
    global queryid

    # If not logged in, send to login page and stop
    if not logged_in:
        return redirect(url_for('login'))

    queries = session.query(Query_Record).filter(Query_Record.query_ID == queryid).first()

    return render_template("query.html", title="Query Review", query=True, queries= queries, queryid=queryid, logged_in=logged_in, user_logged_in=user_logged_in)

# Logins history page
@app.route("/login_history", methods=['GET','POST'])
def login_history():

    form = LogHistoryForm()
    global user_logged_in
    global logged_in
    global queryid
    global user_search_id

    # If not logged in, send to login page and stop
    if not logged_in:
        return redirect(url_for('login'))
    
    if user_logged_in == 1:
        return redirect(url_for('login'))

    users = session.query(Log_Record).filter(Log_Record.query_ID == user_search_id).first()

    return render_template("login_history.html", title="Login History", login_history=True, form=form, users= users, user_search_id=user_search_id, logged_in=logged_in, user_logged_in=user_logged_in)

# FORMS -----------------------------------------------------------------------------------------------------------------------------
class LoginForm(FlaskForm):
    uname = StringField("Enter Username", validators=[DataRequired(), Length(min=2,max=55)])
    pword = PasswordField("Enter Password", validators=[DataRequired(), Length(min=4,max=15)])
    ID_2fa = StringField("Enter 2FA", validators=[DataRequired(), Length(min=2,max=55)])
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    uname = StringField("Create Username", validators=[DataRequired(),Length(min=2,max=55)])
    pword = PasswordField("Enter Password", validators=[DataRequired(),Length(min=4,max=15)])
    ID_2fa = StringField("Set 2FA", validators=[DataRequired(),Length(min=2,max=55)])
    password_confirm = PasswordField("Confirm Password", validators=[DataRequired(),Length(min=4,max=15), EqualTo('pword')])
    submit = SubmitField("Register Now")


class SpellCheckForm(FlaskForm):
    inputtext = StringField("Enter Text to Spell Check", validators=[DataRequired(), Length(min=2,max=5000)])
    check_spelling = SubmitField("Check Spelling")


class QueryForm(FlaskForm):
    userquery = StringField("Enter Username")
    userquery_submit = SubmitField("Search for User")
    
    query_review = StringField("Enter Query ID")
    queryreview_submit = SubmitField("Review Query")
    

class LogHistoryForm(FlaskForm):
    userquery = StringField("Enter ID")
    userquery_submit = SubmitField("Search for User")

# Main -------------------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    # Turn-off debig settings
    app.debug = False

    # Start
    app.run()  