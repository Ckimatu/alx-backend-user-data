#!/usr/bin/env python3
"""
Module for authentication using Basic auth
"""


from typing import TypeVar
from api.v1.auth.auth import Auth
import base64

from models.user import User


class BasicAuth(Auth):
    """for authentication
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header
        for a Basic Authentication:
            Return None if authorization_header is None
            Return None if authorization_header is not a string
            Return None if authorization_header doesn’t start by
            Basic (with a space at the end)
            Otherwise, return the value after Basic (after the space)
            You can assume authorization_header contains only one Basic
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None

        token = authorization_header.split(' ')[-1]
        return token

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns the decoded value of a Base64 string
        base64_authorization_header:
        Return None if base64_authorization_header is None
        Return None if base64_authorization_header is not a string
        Return None if base64_authorization_header is not a valid Base64
        - you can use try/except
        Otherwise, return the decoded value as UTF8 string
        - you can use decode('utf-8')
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            item_to_decode = base64_authorization_header.encode('utf-8')
            decoded = base64.b64decode(item_to_decode)
            return decoded.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """returns the user email and password from the Base64 decoded value
        This method must return 2 values
        Return None, None if decoded_base64_authorization_header is None
        Return None, None if decoded_base64_authorization_header
        is not a string
        Return None, None if decoded_base64_authorization_header
        doesn’t contain :
        Otherwise, return the user email and the user password
        - these 2 values must be separated by a :
        Assume decoded_base64_authorization_header will contain only one :
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        email, password = decoded_base64_authorization_header.split(':')
        return (email, password)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on his email and password.
        Return None if user_email is None or not a string
        Return None if user_pwd is None or not a string
        Return None if your database (file) doesn’t contain
        any User instance with email equal to user_email
        Return None if user_pwd is not the password of the
        User instance found - you must use the method is_valid_password
        of User
        Otherwise, return the User instance
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({"email": user_email})
            if not users or users == []:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """overloads Auth and retrieves the User instance for a request
        """
        auth_header = self.authorization_header(request)
        if auth_header is not None:
            token = self.extract_base64_authorization_header(auth_header)
            if token is not None:
                decoded = self.decode_base64_authorization_header(token)
                if decoded is not None:
                    email, password = self.extract_user_credentials(decoded)
                    if email is not None:
                        return self.user_object_from_credentials(
                            email, password)

        return
