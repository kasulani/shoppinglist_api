from functools import wraps
from flask import request, jsonify, make_response
from app import shoplist_api
import re


def validate_data(data):
    """
    This method will validate data posted to the API
    :param data:
    :return:
    """
    email_regex = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    password_regex = re.compile(r"[A-Za-z0-9@#$%^&+=]{4,}")
    errors = {}  # dictionary of errors, where they {key} is the field name and {value} is the error message
    # inspect the fields in the data for errors
    print (data['username'])
    try:
        if not email_regex.match(data['username']):
            errors['username'] = "please provide a valid email address"
    except Exception as ex:
        shoplist_api.logger.info(ex.message)
    try:
        if not password_regex.match(data['password']) or password_regex.match(data['new_password']):
            errors['password'] = "please provide a valid password with of at least 4 characters with " \
                                 "one uppercase character, one lower case character, a number and any of the " \
                                 "following special characters[@#$%^&+=]"
    except Exception as ex:
        shoplist_api.logger.info(ex.message)
    #
    if len(errors) > 0:
        return make_response(
            jsonify({'status': 'fail', 'message': 'invalid data', 'errors': errors})), 400


def get_token():
    """This method will extract a token from the Authorization header"""
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
        return token
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
        return None


def validate_content_type(f):
    """Decorator to validate the content type json"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('content-type') != 'application/json':
            shoplist_api.logger.error("content-type not specified as application/json")
            return make_response(
                jsonify({'status': 'fail', 'message': 'content-type not specified as application/json'})), 400
        try:
            if len(args) == 0 and len(kwargs) == 0:
                return f()
            else:
                return f(*args, **kwargs)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return make_response(jsonify({'status': 'fail', 'message': ex.message})), 500
    return decorated_function


def validate_token(f):
    """Decorator to validate if token has been provided in the headers"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token()
        #
        if token is None:  # This condition is true when no Authorization header is present in the request
            return make_response(jsonify({'status': 'fail', 'message': 'no access token'})), 401
        try:
            if len(args) == 0 and len(kwargs) == 0:
                return f()
            else:
                return f(*args, **kwargs)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return make_response(jsonify({'status': 'fail', 'message': ex.message})), 500
    return decorated_function
