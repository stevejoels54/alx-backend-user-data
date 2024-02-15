#!/usr/bin/env python3
"""
Module for handling Session authentication routes
"""

from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from api.v1.auth.session_auth import SessionAuth

sa = SessionAuth()


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def auth_session_login() -> str:
    """ POST /api/v1/auth_session/login
    Return:
      - User object JSON represented
      - 400 if the User doesn't exist
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if email is None or password is None:
        return jsonify({"error": "email or password missing"}), 400
    user = User.search({"email": email})
    if len(user) == 0 or not user[0].is_valid_password(password):
        return jsonify({"error": "no user found for this email/password"}), 400
    session_id = sa.create_session(user[0].id)
    response = jsonify(user[0].to_json())
    response.set_cookie("session_id", session_id)
    return response


@app_views.route('/auth_session/logout',
                 methods=['DELETE'], strict_slashes=False)
def auth_session_logout() -> str:
    """ DELETE /api/v1/auth_session/logout
    Return:
      - empty JSON if the User has been correctly deleted
    """
    if sa.destroy_session(request):
        return jsonify({}), 200
    abort(404)
    return None
