#!/usr/bin/env python3
"""Basic authentication module for the API.
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """BasicAuth class.
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """Extracts the base64 part of the Authorization header.
        """
        if (authorization_header is None or
                type(authorization_header) is not str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """Decodes a base64 string.
        """
        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """Extracts the user credentials from a decoded base64 string.
        """
        if (decoded_base64_authorization_header is None or
                type(decoded_base64_authorization_header) is not str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on the email and password.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user.
        """
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        b64_auth_header = self.extract_base64_authorization_header(auth_header)
        if b64_auth_header is None:
            return None
        decoded_b64_auth_header = self.decode_base64_authorization_header(
            b64_auth_header)
        if decoded_b64_auth_header is None:
            return None
        user_email, user_pwd = self.extract_user_credentials(
            decoded_b64_auth_header)
        if user_email is None or user_pwd is None:
            return None
        return self.user_object_from_credentials(user_email, user_pwd)
