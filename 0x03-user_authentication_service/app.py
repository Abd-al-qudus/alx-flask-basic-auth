#!/usr/bin/env python3
"""flask app for the auth service"""
from sqlalchemy.exc import NoResultFound
from flask import Flask
from flask import (
    jsonify,
    abort,
    request,
    redirect
)
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def home() -> str:
    """home page for flask routes"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def register_user() -> str:
    """register users from form data"""
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(400)

    try:
        AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400
    return jsonify({"email": email, "message": "user created"})


@app.route('/sessions', methods=['POST'])
def login():
    """login route"""
    email = request.form.get('email')
    password = request.form.get('password')
    if not email or not password:
        abort(400)
    if AUTH.valid_login(email=email, password=password):
        payload = {"email": email, "message": "logged in"}
        return jsonify(payload)
    else:
        abort(401)

@app.route('/sessions', methods=['DELETE'])
def logout():
    "destroy the user session"
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')

@app.route('/profile', methods=['GET'])
def profile():
    """get the user profile"""
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is not None:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)

@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    """reset user password"""
    email = request.form.get('email')
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "reset_token": reset_token}), 200

@app.route('/reset_password', methods=['PUT'])
def update_password():
    """update the user password"""
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
