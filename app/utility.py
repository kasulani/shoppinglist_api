from functools import wraps
from flask import request, jsonify, make_response
from app import shoplist_api, models


def get_token():
    """This function gets the token from the header of the request"""
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
        return token
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
        return None


def select_func_to_return(f, *args, **kwargs):
    """
    This function selects which function to return depending
    on number of parameters the decorated function expects
    """
    try:
        if len(args) == 0 and len(kwargs) == 0:
            return f()
        else:
            return f(*args, **kwargs)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
        return \
            make_response(
                jsonify(
                    {
                        'status': 'fail',
                        'message': ex.message
                    })), 500


def validate_content_type(f):
    """This function validates the content type in the request"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('content-type') != 'application/json':
            shoplist_api.logger.\
                error("content-type not specified as application/json")
            return make_response(
                jsonify(
                    {
                        'status': 'fail',
                        'message':
                            'content-type not specified as application/json'
                    })), 400
        return select_func_to_return(f, *args, **kwargs)
    return decorated_function


def validate_token(f):
    """This function validates the token passed in the request"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_token()

        # This condition is true when no Authorization
        # header is present in the request
        if token is None:
            return \
                make_response(
                    jsonify(
                        {
                            'status': 'fail',
                            'message': 'no access token'
                        })), 401
        #
        try:
            # decode the user id from the token to make sure it's a genuine
            user_id = models.User.decode_token(token)
            user = models.User.query.filter_by(user_id=user_id).first()
            if user.token != token:
                return \
                    make_response(
                        jsonify(
                            {
                                'status': 'fail',
                                'message': 'mismatching or wrong token'
                            })), 401
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return \
                make_response(
                    jsonify(
                        {
                            'status': 'fail',
                            'message': ex.message
                        })), 500
        #
        return select_func_to_return(f, *args, **kwargs)
    return decorated_function
