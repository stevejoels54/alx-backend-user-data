#!/usr/bin/env python3
""" 3. Auth class
"""

from flask import request
from typing import List, TypeVar
import re
from os import getenv


class Auth:
    """Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require auth
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != '/':
            path += '/'
        for p in excluded_paths:
            if p[-1] != '/':
                p += '/'
            p = p.replace('*', '.*')
            if re.match(p, path):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Authorization header
        """
        if request is None or "Authorization" not in request.headers:
            return None
        return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user
        """
        return None

    def session_cookie(self, request=None):
        """Session cookie
        """
        if request is None:
            return None
        session_name = getenv("SESSION_NAME")
        return request.cookies.get(session_name)
