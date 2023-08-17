#!/usr/bin/env python3

"""module auth
"""


import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4

from typing import Union


def _hash_password(password: str) -> str:
    """takes in a password string arguments and returns bytes
    The returned bytes is a salted hash of the input password,
    hashed with bcrypt.hashpw
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """return a string representation of a new UUID
    """
    id = uuid4()
    return str(id)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """initialization
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> Union[None, User]:
        """take mandatory email and password string arguments
        and return a User object
        """
        try:
            # find the user with the given email
            self._db.find_user_by(email=email)
        except NoResultFound:
            # add user to database
            return self._db.add_user(email, _hash_password(password))

        else:
            # if user already exists, throw error
            raise ValueError('User {} already exists'.format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Try locating the user by email
        If it exists, check the password with bcrypt.checkpw.
        If it matches return True. In any other case, return False
        """
        try:
            # find the user with the given email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        # check validity of password
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> str:
        """ find the user corresponding to the email,
        generate a new UUID and store it in the database
        as the user’s session_id, then return the session ID.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        else:
            user.session_id = _generate_uuid()
            return user.session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """takes a single session_id string argument
        and returns the corresponding User or None
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return user

    def destroy_session(self, user_id: str) -> None:
        """updates the corresponding user’s session ID to None
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None
        else:
            user.session_id = None
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Find the user corresponding to the email.
        If the user does not exist, raise a ValueError exception.
        If it exists, generate a UUID and update the
        user’s reset_token database field.
        Return the token
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        else:
            user.reset_token = _generate_uuid()
            return user.reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Use the reset_token to find the corresponding user
        If it does not exist, raise a ValueError exception
        Otherwise, hash the password and update the
        user’s hashed_password field with the new hashed password
        and the reset_token field to None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        else:
            user.hashed_password = _hash_password(password)
            user.reset_token = None
            return None
