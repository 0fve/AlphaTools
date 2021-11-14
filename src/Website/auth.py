from flask import Blueprint, render_template, request, redirect, url_for, abort, flash, session, current_app
from flask_login import login_required, current_user, logout_user, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_admin.contrib.sqla import ModelView
from flask_login.utils import login_user
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFError
from flask_wtf import CSRFProtect
from flask.helpers import flash
from .models import User, tools
from flask_admin import Admin
from flask.app import Flask
from . import db, alpha
from . import safeURL
import time


alpha = alpha()

auth = Blueprint('auth', __name__)




@auth.route('/Login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect(url_for('auth.account'))

        elif current_user.is_authenticated == False:
            return render_template("login.html", user=current_user)


        return render_template("login.html", user=current_user)

    elif request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        if '@' in email:
            user = User.query.filter_by(email=email).first()
        else:
            username = email
            user = User.query.filter_by(username=username).first()

        # new_user = User(email=email, password=generate_password_hash(password, 'sha256'))
        # db.session.add(new_user)
        # db.session.commit()
        # z3brishere
        
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                if user.admin == True:
                    return redirect(url_for('auth.area51'))

                else:
                    return redirect(url_for('views.home'))

            elif not check_password_hash(user.password, password):
                flash('Wrong username or password.', category='error')
                return redirect(url_for('auth.login'))

        elif not user:
            flash('Email doesn\'t exist.', category='error')
            return render_template("login.html", user=current_user)


    else:
        return render_template("login.html", user=current_user)


# new_user = User(email=email, password=generate_password_hash(password, 'sha256'))
#   db.session.add(new_user)
#    db.session.commit()




@auth.route('/signup', methods=["GET", "POST"])
def signup():


    if current_user.is_authenticated:

        return redirect(url_for('views.home'))


    elif request.method == 'POST':
        firstName = request.form.get('firstName')
        lastName = request.form.get('lastName')
        username = request.form.get('username')
        user_email = request.form.get('email')
        password = request.form.get('password')
        passwordConfirm  = request.form.get('passwordConfirm')


        user = User.query.filter_by(email=user_email).first()

        if user:
            flash('Email already exists.', category='error')

        elif len(firstName) < 2:
            flash('First name must be greater than 1 character.', category='error')

        elif len(lastName) < 2:
            flash('First name must be greater than 1 character.', category='error')

        elif len(username) < 4:
            flash('Username must be greater than 3 characters.', category='error')

        elif len(user_email) < 4:
            flash('Email must be greater than 3 characters.', category='error')

        elif password != passwordConfirm:
            flash('Passwords don\'t match.', category='error')

        elif len(password) < 7:
            flash('Password must be at least 7 characters.', category='error')

        else:
            new_user = User(email=user_email, username=username, firstName=firstName, lastName=lastName, password=generate_password_hash(password, method='sha256'))

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            alpha.send_message_confirmation(user_email, current_app)

            return redirect(url_for('views.confirm'))

    return render_template('SignUp.html', user=current_user)

@auth.route('/newConfirmationLink', methods=["GET"])
def newConfirmationLink():
    alpha.send_message_confirmation(current_user.email, current_app)

@auth.route('/confirmation/<token>')
def confirm(token):
    try:
        email = safeURL.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(username=current_user.username).first()
        user.verified = True
        db.session.commit()
        return render_template("emailStats.html", user=current_user, confirmed=True)

    except SignatureExpired:
        return render_template("emailStats.html", user=current_user, confirmed=False)

@auth.route('/Account')
def account():


    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    elif current_user.is_authenticated:
        # user = User.query.filter_by(username=current_user.username).first()

        return render_template('account.html', user=current_user)

        
    return render_template('account.html', user=current_user)


@auth.route('/forgotPassword/', methods=['POST','GET'])
def forget():
    
    if request.method == 'POST':
        email_from_request = request.form.get('email')
        user = User.query.filter_by(email=email_from_request).first()

        if user:
            print(user.email)
            alpha.send_message_reset(user.email, current_app)
            flash("Email sent successfully", category='success')

        else:
            flash("This email does not exist", category='error')

    return render_template('forget password.html', user=current_user)

@auth.route('/reset_password/<token>', methods=['POST','GET'])
def reset_password(token):
    try:
        age = safeURL.loads(token, salt='email-confirm', max_age=3600)
        password = request.form.get('password')
        passwordConfirm = request.form.get('passwordConfirm')

        if request.method == 'POST':
            
            if password != passwordConfirm:
                flash('Passwords don\'t match.', category='error')

            elif len(password) < 7:
                flash('Password must be at least 7 characters.', category='error')
            
            else:
                current_user.password = generate_password_hash(password, method='sha256')
                db.session.commit()
                flash('Password was reset successfully', category='success')
                return redirect(url_for('views.home'))

        return render_template('reset_password.html', user=current_user)

    
    except SignatureExpired:
        return render_template("expired.html", user=current_user, confirmed=False)
    

@auth.route('/Logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/area51', methods=["GET", "POST"])
def area51():

    request.headers.get("cookie")
    category= ''
    if request.method == "GET":
        # print(request.referrer)
        # flash('Please Login', category='error')
        # return render_template("area51.html", user=current_user)

        if current_user.is_authenticated and not current_user.admin:
            return render_template("errors400.html", user=current_user)

        elif current_user.is_authenticated and current_user.admin:
            return render_template("area51.html", user=current_user)

        else:
            return redirect(url_for('views.home'))

    elif request.method == "POST":

        toolStatus = request.form.get('Avaliable')

        if request.form.get('Avaliable'):

            toolName = request.form.get('toolName')
            tool = tools.query.filter_by(toolName=toolName).first()
            tool.toolStatus = True
            db.session.commit()

        elif request.form.get('Unavaliable'):
            toolName = request.form.get('toolName')
            tool = tools.query.filter_by(toolName=toolName).first()
            tool.toolStatus = False
            db.session.commit()

    else:
        abort(500)

    return render_template("area51.html", user=current_user)



@auth.route('/thanks')
def thanks():
    return render_template("purchased.html", user=current_user)

@auth.route('/canceled')
def canceled():
    return render_template("canceled.html", user=current_user)