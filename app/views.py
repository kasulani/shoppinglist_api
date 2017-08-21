"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
----------------------------------------------------------------------------------------------
    Endpoints here
"""
from app import shoplist_api
from app import models
from flask_httpauth import HTTPTokenAuth
from flask import request, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
auth = HTTPTokenAuth(scheme='Token')


@shoplist_api.route('/auth/register', methods=['POST'])
def register():
    """
    This endpoint will create a user account in the shopping list application
    :return:
    """
    if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
        data = request.json
        shoplist_api.logger.debug("/auth/register: incoming request data %s " % data)
        if 'username' in data and 'email' in data and 'password' in data:
            # create user in the database
            user = models.User(username=data['username'],
                               email=data['email'],
                               password=generate_password_hash(data['password']))
            # todo: hash the password before storing the password
            user.add()
            shoplist_api.logger.debug("created user %s " % user.username)
            response = jsonify({'username': user.username,
                                # 'email': user.email,
                                # 'password': user.password
                                })
            return response, 200
        shoplist_api.logger.error("bad or missing parameter(s) in json")
        return jsonify({'error': 'bad parameter(s)'}), 400
    shoplist_api.logger.error("bad request to endpoint /auth/register")
    return abort(400)


@shoplist_api.route('/auth/login', methods=['POST'])
def login():
    """
    This endpoint will login a user with an account
    :return:
    """
    if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
        data = request.json
        shoplist_api.logger.debug("/auth/login: incoming request data %s " % data)
        if 'username' in data and 'password' in data:
            # check username and password are correct
            user = models.User.query.get(data['username'])
            if user and check_password_hash(data['password'], user.password):
                # generate token here
                token = user.generate_auth_token()
                shoplist_api.logger.debug("user %s has logged in successfully" % data['username'])
                return jsonify({'token': token.decode('ascii'), 'duration': 600}), 200
            shoplist_api.logger.error("wrong password or username")
            return jsonify({'error': 'wrong password or username'}), 400
    shoplist_api.logger.error("bad request to endpoint /auth/login")
    return abort(400)


@shoplist_api.route('/auth/logout')
def logout():
    pass


@shoplist_api.route('/auth/reset-password', methods=['POST'])
def reset_password():
    """
    This endpoint will reset a password for a given user logged in at the front end
    :return:
    """
    if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
        data = request.json
        shoplist_api.logger.debug("/auth/reset: incoming request data %s " % data)
        if 'username' in data and 'new_password' in data and 'old_password' in data:
            # locate user and check the old password
            user = models.User.query.get(data['username'])
            if user and check_password_hash(user.password, data['old_password']):
                user.password = generate_password_hash(data['new_password'])
                return jsonify({'username': user.username}), 200
            shoplist_api.logger.error("wrong username or password")
            return jsonify({'error': 'wrong username or password'}), 400
        shoplist_api.logger.error("bad or missing parameter(s) in json")
        return jsonify({'error': 'bad parameter(s)'}), 400
    shoplist_api.logger.error("bad request to endpoint /auth/reset")
    return abort(400)

# -------------------------------------------------------------------------------------------------


@auth.login_required
@shoplist_api.route('/shoppinglists')
def create_list():
    pass


@auth.login_required
@shoplist_api.route('/shoppinglists')
def view_lists():
    pass


@auth.login_required
@shoplist_api.route('/shoppinglists/<int:list_id>')
def get_list(list_id):
    # todo: return pagenated results
    pass


@auth.login_required
@shoplist_api.route('/shoppinglists/<int:list_id>')
def update_list(list_id):
    pass


@auth.login_required
@shoplist_api.route('/shoppinglists/<int:list_id>')
def delete_list(list_id):
    pass
# -------------------------------------------------------------------------------------------------@auth.login_required


@auth.login_required
@shoplist_api.route('/shoppinglists/<int:list_id>/items')
def add_items_list(list_id):
    pass


@auth.login_required
@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>')
def update_list_item(list_id, item_id):
    pass


@auth.login_required
@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>')
def delete_item_from_list(list_id, item_id):
    pass
# -------------------------------------------------------------------------------------------------



