#!/usr/bin/env python3
"""this module contains the authentication methods
    for the authentication services API"""
import bcrypt
from db import DB
from user import User
from typing import Union
from sqlalchemy.orm.exc import NoResultFound
import bcrypt
import uuid


def _hash_password(password: str) -> bytes:
    """returns bytes from hashed password"""
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed_pw

def _generate_uuid() -> str:
    """generate random uuid"""
    return str(uuid.uuid4())


class Auth:
    """a class to handle the Authentication states"""

    def __init__(self) -> None:
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """register the user in the database"""
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                raise ValueError('User {} already exists.'.format(email))
        except NoResultFound:
            hashed_pw = _hash_password(password)
            user = self._db.add_user(email=email, hashed_password=hashed_pw)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """check whether user has a valid login credentials"""
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return bcrypt.checkpw(password.encode('utf-8'),
                                      user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """generate the session id and store it in user session_id"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """get user from session id"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """destroy session id"""
        try:
            self._db.update_user(user_id=user_id, session_id=None)
        except NoResultFound:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """generate password reset token"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        passwd_reset = _generate_uuid()
        self._db.update_user(user.id, reset_token=passwd_reset)
        return passwd_reset

    def update_password(self, reset_token: str, password: str) -> None:
        """reset user password with reset token"""
        user = self._db.find_user_by(reset_token=reset_token)
        if user is None:
            raise ValueError
        passwd_hash = _hash_password(password)
        self._db.update_user(user.id, hashed_password=passwd_hash, reset_token=None)
        