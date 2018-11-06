import functools

from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from mimi.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute('SELECT id FROM user WHERE username = ?', (username,)).fetchone() is not None:
            error = f'User {username} is already registered'
        
        if error is None:
            db.execute('INSERT INTO user (username, password) VALUES (?, ?)', (username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)
    return render_template('auth/register.html')


@bp.route('/login', methods=('GET','POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        error = None
        user = db.execute('SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user in None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id'] #session is a dict that stores data across requests
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

#loading user info to be available to other views after logging in
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id, )
        ).fetchone()

#logging out requires one to remove the user id from the session
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

#requiring authentication in other views
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)
    return wrapped_view

#name associated with aview is also called the endpoint and is the same name as the view function
#when using a blueprint, the name of the blueprint is prepended  to the name of the function ie 'auth.login'