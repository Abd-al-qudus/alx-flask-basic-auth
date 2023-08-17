#!/usr/bin/env python3
"""test all entry points"""
import requests


BASE_URL = 'http://localhost:5000'


def register_user(email, password):
    response = requests.post(f"{BASE_URL}/users", data={'email': email, 'password': password})
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}

def log_in_wrong_password(email, password):
    response = requests.post(f"{BASE_URL}/sessions", data={'email': email, 'password': password})
    assert response.status_code == 401

def log_in(email, password):
    response = requests.post(f"{BASE_URL}/sessions", data={'email': email, 'password': password})
    assert response.status_code == 200
    return response.cookies.get('session_id')

def profile_unlogged():
    response = requests.get(f"{BASE_URL}/profile")
    assert response.status_code == 403

def profile_logged(session_id):
    cookies = {'session_id': session_id}
    response = requests.get(f"{BASE_URL}/profile", cookies=cookies)
    # assert response.status_code == 200
    assert response.json() == {"email": "user@example.com"}

def log_out(session_id):
    cookies = {'session_id': session_id}
    response = requests.delete(f"{BASE_URL}/sessions", cookies=cookies)
    assert response.status_code == 302  # Redirect status code

def reset_password_token(email):
    response = requests.post(f"{BASE_URL}/reset_password", data={'email': email})
    assert response.status_code == 200
    return response.json().get('reset_token')

def update_password(email, reset_token, new_password):
    data = {'email': email, 'reset_token': reset_token, 'new_password': new_password}
    response = requests.put(f"{BASE_URL}/reset_password", data=data)
    assert response.status_code == 200


if __name__ == "__main__":
    EMAIL = "guillaume@holberton.io"
    PASSWD = "b4l0u"
    NEW_PASSWD = "t4rt1fl3tt3"
    
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
