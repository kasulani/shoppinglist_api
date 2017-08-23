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
        if 'email' in data and 'password' in data:
            # check if the user exists in the db
            user = models.User.query.filter_by(email=data['email']).first()
            if user is None:
                # create user in the database
                user = models.User(email=data['email'],
                                   password=generate_password_hash(data['password']))
                user.add()
                shoplist_api.logger.debug("created user %s " % user.email)
                return jsonify({'username': user.email}), 200
            return jsonify({'status': 'user already exists'}), 200
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
            # locate the user
            user = models.User.query.filter_by(email=data['username']).first()
            # authenticate user
            shoplist_api.logger.debug("/auth/register: incoming request data %s " % user)
            if user and check_password_hash(user.password, data['password']):
                # generate token here
                token = user.generate_auth_token()
                if token:
                    shoplist_api.logger.debug("user %s has logged in successfully" % data['username'])
                    return jsonify({'token': token.decode('ascii'), 'status': 'login was successful'}), 200
            shoplist_api.logger.error("wrong password or username")
            return jsonify({'error': 'wrong password or username'}), 401
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
            user = models.User.query.filter_by(email=data['username']).first()
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


@shoplist_api.route('/shoppinglists', methods=['POST'])
def create_list():
    """
    This endpoint will create a shopping list for a logged in user
    :return:
    """
    # Get the access token from the header
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]
    shoplist_api.logger.debug("token: %s " % token)
    #
    if token:
        user_id = models.User.decode_token(token)
        shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
        if isinstance(int(user_id), int):
            if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
                data = request.json
                shoplist_api.logger.debug("/shoppinglists: incoming request data %s " % data)
                if 'title' in data:
                    try:
                        description = data['description']
                    except Exception as ex:
                        shoplist_api.logger.error(ex.message)
                        description = ""
                    # create a list
                    the_list = models.List(user_id=int(user_id),
                                           list_name=data['title'],
                                           description=description)
                    the_list.add()
                    shoplist_api.logger.debug("created list:{0} for user:{1}".format(the_list.list_name,
                                                                                     the_list.username))
                    response = jsonify({'user_id': the_list.username,
                                        'title': the_list.list_name,
                                        })
                    return response, 200
                shoplist_api.logger.error("bad or missing parameter(s) in json")
                return jsonify({'error': 'bad parameter(s)'}), 400
            shoplist_api.logger.error("bad request to endpoint /shoppinglists")
        return abort(400)
    shoplist_api.logger.error("no access token")
    return jsonify({'error': 'no access token'}), 401


@shoplist_api.route('/shoppinglists', methods=['GET'])
def view_all_lists():
    """
    This endpoint will return all the lists for a logged in user
    :return:
    """
    # Get the access token from the header
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]
    shoplist_api.logger.debug("token: %s " % token)
    #
    if token:
        user_id = models.User.decode_token(token)
        shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
        if isinstance(int(user_id), int):
            lists = models.List.query.filter_by(username=user_id)
            if lists is not None:
                results = []
                for a_list in lists:
                    result = {
                        'id': a_list.list_id,
                        'title': a_list.list_name,
                        'description': a_list.description
                    }
                    results.append(result)
                return jsonify(results), 200
            return jsonify({'status': 'no records found'}), 200
        abort(400)
    shoplist_api.logger.error("no access token")
    return jsonify({'error': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['GET'])
def get_list(list_id):
    """
    This endpoint will return a list of a given id
    :param list_id:
    :return:
    """
    # Get the access token from the header
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]
    shoplist_api.logger.debug("token: %s " % token)
    #
    if token:
        user_id = models.User.decode_token(token)
        shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
        if isinstance(int(user_id), int):
            a_list = models.List.query.filter_by(list_id=list_id, username=user_id).first()
            if a_list is not None:
                response = jsonify({
                    'id': a_list.list_id,
                    'title': a_list.list_name,
                    'description': a_list.description
                })
                return response, 200
            return jsonify({'status': 'no record found'}), 200
        abort(400)
    shoplist_api.logger.error("no access token")
    return jsonify({'error': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['PUT'])
def update_list(list_id):
    """
    This endpoint will update a list of with a given id
    :param list_id:
    :return:
    """
    # Get the access token from the header
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]
    shoplist_api.logger.debug("token: %s " % token)
    #
    if token:
        user_id = models.User.decode_token(token)
        shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
        if isinstance(int(user_id), int):
            the_list = models.List.query.filter_by(list_id=list_id, username=user_id).first()
            data = request.json
            shoplist_api.logger.debug("/shoppinglists/<id>: incoming request data %s " % data)
            if the_list is not None and 'title' in data:
                try:
                    description = data['description']
                except Exception as ex:
                    shoplist_api.logger.error(ex.message)
                    description = ""

                the_list.list_name = data['title']
                the_list.description = description
                the_list.update()
                response = jsonify({
                    'id': the_list.list_id,
                    'title': the_list.list_name,
                    'description': the_list.description
                })
                return response, 200
            return jsonify({'status': 'no record found'}), 200
        abort(404)
    shoplist_api.logger.error("no access token")
    return jsonify({'error': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['DELETE'])
def delete_list(list_id):
    """
    This endpoint will delete a list with a given id
    :param list_id:
    :return:
    """
    # Get the access token from the header
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]
    shoplist_api.logger.debug("token: %s " % token)
    #
    if token:
        user_id = models.User.decode_token(token)
        shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
        if isinstance(int(user_id), int):
            the_list = models.List.query.filter_by(list_id=list_id, username=user_id).first()
            if the_list is not None:
                the_list.delete()
                return jsonify({'status': 'shopping list {} has been deleted successfully'.format(list_id)})
            return jsonify({'status': 'no record found'}), 200
        abort(404)
    shoplist_api.logger.error("no access token")
    return jsonify({'error': 'no access token'}), 401


# -------------------------------------------------------------------------------------------------@auth.login_required


@shoplist_api.route('/shoppinglists/<int:list_id>/items', methods=['POST'])
def add_items_list(list_id):
    # Get the access token from the header
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]
    shoplist_api.logger.debug("token: %s " % token)
    #
    if token:
        user_id = models.User.decode_token(token)
        shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
        if isinstance(int(user_id), int):
            if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
                data = request.json
                if 'name' in data:
                    try:
                        description = data['description']
                    except Exception as ex:
                        shoplist_api.logger.error(ex.message)
                        description = ""
                    # add an item to the list
                    item = models.Item(item_name=data['name'],
                                       list_id=list_id,
                                       description=description)
                    item.add()
                    shoplist_api.logger.debug("added item:{0}".format(item.item_name))
                    return jsonify({'item': item.item_name}), 200
                shoplist_api.logger.error("bad or missing parameter(s) in json")
                return jsonify({'error': 'bad parameter(s)'}), 400
            shoplist_api.logger.error("bad request to endpoint /shoppinglists")
            return abort(400)
        return abort(400)
    shoplist_api.logger.error("no access token")
    return jsonify({'error': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>', methods=['PUT'])
def update_list_item(list_id, item_id):
    # Get the access token from the header
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]
    shoplist_api.logger.debug("token: %s " % token)
    #
    if token:
        user_id = models.User.decode_token(token)
        shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
        if isinstance(int(user_id), int):
            the_item = models.Item.query.filter_by(list_id=list_id, item_id=item_id).first()
            data = request.json
            shoplist_api.logger.debug("/shoppinglists/<int:list_id>/items/<int:item_id>: incoming request data %s " % data)
            if the_item is not None and 'name' in data:
                try:
                    description = data['description']
                except Exception as ex:
                    shoplist_api.logger.error(ex.message)
                    description = ""

                the_item.item_name = data['name']
                the_item.description = description
                the_item.update()
                return jsonify({'item': the_item.item_name}), 200
            return jsonify({'status': 'no record found'}), 200
        abort(404)
    shoplist_api.logger.error("no access token")
    return jsonify({'error': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>', methods=['DELETE'])
def delete_item_from_list(list_id, item_id):
    """
    This endpoint will delete an item on given list
    :param list_id:
    :return:
    """
    # Get the access token from the header
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1]
    shoplist_api.logger.debug("token: %s " % token)
    #
    if token:
        user_id = models.User.decode_token(token)
        shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
        if isinstance(int(user_id), int):
            the_item = models.Item.query.filter_by(list_id=list_id, item_id=item_id).first()
            if the_item is not None:
                item_name = the_item.item_name
                the_item.delete()
                shoplist_api.logger.debug("item %s has been deleted successfully" % item_name)
                return jsonify({'status': 'item {} has been deleted successfully'.format(item_name)})
            return jsonify({'status': 'no record found'}), 200
        abort(404)
    shoplist_api.logger.error("no access token")
    return jsonify({'error': 'no access token'}), 401
# -------------------------------------------------------------------------------------------------



