from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth',__name__)


@auth.route('/login', methods=[ 'GET', 'POST'])
def login():
    return render_template("login.html")


@auth.route('/logout')
def logout():
    return "<p>logout</p>"


@auth.route('sign-up', methods=[ 'GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstname')
        password1 = request.form.get('Password1')
        password2 = request.form.get('Password2')
        print(password1)
        print(password2)

        if int(len(str(email))) < 4:
            flash('Email must be greater than 3 characters.', category="error")
        elif int(len(str(first_name))) < 2:
            flash('first name must be greater than 1 character.', category="error")
        elif str(password1) != str(password2):
            flash('passwords don\'t match.', category="error")
        elif int(len(str(password1))) < 7:
            flash('password must be at least 7 characters.', category="error")
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
            
    return render_template("sign_up.html")
