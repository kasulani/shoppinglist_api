"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
----------------------------------------------------------------------------------------------
    Endpoints here
"""
from app import shoplist_api, login_manager
from app import models
from flask import request, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user


@login_manager.user_loader
def load_user(email):
    """
    This methods loads a user from the database. This method is required for flask_login to work
    :param email:
    :return: user object
    """
    return models.User.query.filter_by(email=email).first()


@shoplist_api.route('/auth/register', methods=['POST'])
def register():
    """
    This endpoint will create a user account in the shopping list application
    :return:
    """
    if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
        data = request.json
        shoplist_api.logger.debug("/auth/register: incoming request data %s " % data)
        try:
            if 'username' in data and 'password' in data:
                # check if the user exists in the db
                user = models.User.query.filter_by(email=data['username']).first()
                if user is None:
                    # create user in the database
                    user = models.User(email=data['username'],
                                       password=generate_password_hash(data['password']))
                    user.add()
                    shoplist_api.logger.debug("created user %s " % user.email)
                    return jsonify({'username': user.email,
                                    'status': 'pass',
                                    'message': 'user account created successfully'}), 200
                shoplist_api.logger.error("user already exists")
                return jsonify({'status': 'fail', 'message': 'user already exists'}), 200
            shoplist_api.logger.error("bad or missing parameter(s) in json")
            return jsonify({'status': 'fail', 'message': 'bad parameter(s)'}), 200
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("bad request to endpoint /auth/register")
    return abort(400)


@shoplist_api.route('/auth/login', methods=['POST'])
def login():
    """
    This endpoint will login a user with an account
    :return: json response
    """
    if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
        data = request.json
        shoplist_api.logger.debug("/auth/login endpoint: incoming request data %s " % data)
        try:
            if 'username' in data and 'password' in data:
                # locate the user and create a user object
                user = models.User.query.filter_by(email=data['username']).first()
                # log message and authenticate user
                shoplist_api.logger.debug("/auth/login endpoint: authenticating user<%s>" % data['username'])
                if user and check_password_hash(user.password, data['password']):
                    # generate token here
                    token = user.generate_auth_token()
                    login_user(user)
                    if token:
                        # log message and return response to client
                        shoplist_api.logger.debug("user %s has logged in successfully" % data['username'])
                        return jsonify({'token': token.decode('ascii'),
                                        'status': 'pass',
                                        'message': 'login was successful'}), 200
                shoplist_api.logger.error("wrong password or username or may be user does't exist")
                return jsonify({'status': 'fail',
                                'message': 'wrong password or username or may be user does\'t exist'}), 200
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("bad request to endpoint /auth/login")
    return abort(400)


@shoplist_api.route('/auth/logout', methods=['GET'])
@login_required
def logout():
    """
    This endpoint will logout a user
    :return:
    """
    logout_user()
    return jsonify({'status': 'pass', 'message': 'logout was successful'}), 200


@shoplist_api.route('/auth/reset-password', methods=['POST'])
@login_required
def reset_password():
    """
    This endpoint will reset a password for a given user logged in at the front end
    :return:
    """
    if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
        data = request.json
        shoplist_api.logger.debug("/auth/reset: incoming request data %s " % data)
        try:
            if 'username' in data and 'new_password' in data and 'old_password' in data:
                # locate user and check the old password
                user = models.User.query.filter_by(email=data['username']).first()
                if user and check_password_hash(user.password, data['old_password']):
                    user.password = generate_password_hash(data['new_password'])
                    user.update()
                    return jsonify({'username': user.email,
                                    'status': 'pass',
                                    'message': 'password was changed successfully'}), 200
                shoplist_api.logger.error("wrong username or password or may be user does't exist")
                return jsonify({'status': 'fail',
                                'message': 'wrong username or password or may be user does\'t exist'}), 200
            shoplist_api.logger.error("bad or missing parameter(s) in json")
            return jsonify({'status': 'fail', 'message': 'bad parameter(s)'}), 200
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("bad request to endpoint /auth/reset")
    return abort(400)

# -------------------------------------------------------------------------------------------------


@shoplist_api.route('/shoppinglists', methods=['POST'])
@login_required
def create_list():
    """
    This endpoint will create a shopping list for a logged in user
    :return:
    """
    token = None
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
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
                    try:
                        # create a list
                        the_list = models.List(user_id=int(user_id),
                                               list_name=data['title'],
                                               description=description)
                        the_list.add()
                        shoplist_api.logger.debug("created list:<{0}> for user:<{1}>".format(the_list.list_name,
                                                                                             the_list.user_id))
                        response = jsonify({'user_id': the_list.user_id,
                                            'title': the_list.list_name,
                                            'status': 'pass',
                                            'message': 'list created successfully'
                                            })
                        return response, 200
                    except Exception as ex:
                        shoplist_api.logger.error(ex.message)
                        return jsonify({'status': 'fail', 'message': ex.message}), 200

                shoplist_api.logger.error("bad or missing parameter(s) in json")
                return jsonify({'status': 'fail', 'message': 'missing parameter(s)'}), 200
            shoplist_api.logger.error("bad request to endpoint /shoppinglists")
            return jsonify({'status': 'fail', 'message': 'bad request'}), 200
        return abort(401)
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401


@shoplist_api.route('/shoppinglists', methods=['GET'])
@login_required
def view_all_lists():
    """
    This endpoint will return all the lists for a logged in user
    :return:
    """
    token = None
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
    #
    if token:
        try:
            user_id = models.User.decode_token(token)
            if isinstance(int(user_id), int):
                shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
                lists = models.List.query.filter_by(user_id=user_id)
                if lists is not None:
                    results = []
                    for a_list in lists:
                        result = {
                            'id': a_list.list_id,
                            'title': a_list.list_name,
                            'description': a_list.description
                        }
                        results.append(result)
                    return jsonify({'lists': results,
                                    'count': str(len(results)),
                                    'status': 'pass',
                                    'message': 'lists found'}), 200

                return jsonify({'count': '0', 'status': 'pass', 'message': 'no lists found'}), 200
            abort(401)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['GET'])
@login_required
def get_a_list(list_id):
    """
    This endpoint will return a list of a given id
    :param list_id:
    :return: json response
    """
    token = None
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)

    #
    if token:
        try:
            user_id = models.User.decode_token(token)
            if isinstance(int(user_id), int):
                shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
                a_list = models.List.query.filter_by(list_id=list_id, user_id=user_id).first()
                if a_list is not None:
                    shoplist_api.logger.debug("list with id<%s> found" % list_id)
                    response = jsonify({'list': dict(id=a_list.list_id,
                                                     title=a_list.list_name,
                                                     description=a_list.description),
                                        'count': '1',
                                        'status': 'pass',
                                        'message': 'list found'})
                    return response, 200
                shoplist_api.logger.debug("list with id<%s> not found" % list_id)
                return jsonify({'count': '0', 'status': 'pass', 'message': 'list not found'}), 200
            abort(401)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['PUT'])
@login_required
def update_a_list(list_id):
    """
    This endpoint will update a list of with a given id
    :param list_id:
    :return: json response
    """
    token = None
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
    #
    if token:
        try:
            user_id = models.User.decode_token(token)
            if isinstance(int(user_id), int):
                shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
                the_list = models.List.query.filter_by(list_id=list_id, user_id=user_id).first()
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
                    shoplist_api.logger.debug("list with id<%s> has been updated " % the_list.list_id)
                    response = jsonify({'list': dict(id=the_list.list_id,
                                                     title=the_list.list_name,
                                                     description=the_list.description),
                                        'status': 'pass',
                                        'message': 'list updated'})
                    return response, 200
                shoplist_api.logger.error("list with id<%s> has not been updated " % list_id)
                return jsonify({'status': 'fail', 'message': 'list not updated'}), 200
            shoplist_api.logger.error("unknown user id: <%s> " % user_id)
            abort(401)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['DELETE'])
@login_required
def delete_a_list(list_id):
    """
    This endpoint will delete a list with a given id
    :param list_id:
    :return: json response
    """
    token = None
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
    #
    if token:
        try:
            user_id = models.User.decode_token(token)
            if isinstance(int(user_id), int):
                shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
                the_list = models.List.query.filter_by(list_id=list_id, user_id=user_id).first()
                if the_list is not None:
                    the_list.delete()
                    shoplist_api.logger.debug("list with id<%s> has been deleted " % list_id)
                    return jsonify({'status': 'pass', 'message': 'list deleted'})
                return jsonify({'status': 'fail', 'message': 'list not deleted'}), 200
            abort(404)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401


# -------------------------------------------------------------------------------------------------

@shoplist_api.route('/shoppinglists/<int:list_id>/items', methods=['GET'])
@login_required
def get_list_items(list_id):
    """
    This endpoint will return items on a given list
    :param list_id:
    :return: json response
    """
    token = None
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
    #
    if token:
        try:
            user_id = models.User.decode_token(token)
            if isinstance(int(user_id), int):
                shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
                the_list = models.List.query.filter_by(list_id=list_id).first()
                if the_list is not None:
                    items = models.Item.query.filter_by(list_id=list_id)
                    if items is not None:
                        shoplist_api.logger.debug("getting items on list:<%s> " % list_id)
                        results = []
                        for item in items:
                            result = {
                                'id': item.item_id,
                                'name': item.item_name,
                                'description': item.description
                            }
                            results.append(result)
                        return jsonify({'items': results,
                                        'count': str(len(results)),
                                        'status': 'pass',
                                        'message': 'items found'}), 200
                return jsonify({'count': '0', 'status': 'pass', 'message': 'list does not exist'}), 200
            abort(401)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>/items', methods=['POST'])
@login_required
def add_items_list(list_id):
    """
    This endpoint will add items to a given list
    :param list_id:
    :return: json response
    """
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
    #
    if token:
        try:
            user_id = models.User.decode_token(token)
            if isinstance(int(user_id), int):
                shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
                if request.method == 'POST' and request.headers.get('content-type') == 'application/json':
                    the_list = models.List.query.filter_by(list_id=list_id).first()
                    # check to ensure the list exists
                    if the_list is not None:
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
                            shoplist_api.logger.debug("added item:<{0}> to list <{1}>".format(item.item_name, list_id))
                            return jsonify({'item_id': item.item_id,
                                            'status': 'pass', 'message': 'item added to list'}), 200
                        shoplist_api.logger.error("bad or missing parameter(s) in json")
                        return jsonify({'status': 'fail', 'message': 'missing parameter(s)'}), 200
                    shoplist_api.logger.error("list <%s> does not exist" % list_id)
                    return jsonify({'status': 'fail', 'message': 'list does not exist'}), 200
                shoplist_api.logger.error("bad request to endpoint /shoppinglists/<int:list_id>/items")
                return jsonify({'status': 'fail', 'message': 'bad request'}), 200
            return abort(401)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>', methods=['PUT'])
@login_required
def update_list_item(list_id, item_id):
    """
    This endpoint will update a given item on a given list
    :param list_id:
    :param item_id:
    :return: json response
    """
    token = None
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
    #
    if token:
        try:
            user_id = models.User.decode_token(token)
            if isinstance(int(user_id), int):
                shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
                the_list = models.List.query.filter_by(list_id=list_id).first()
                if the_list is not None:
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
                        shoplist_api.logger.debug(
                            "item with id:<{0}> on list with id:<{1}> has been updated ".format(item_id, list_id))
                        return jsonify({'item': dict(id=the_item.item_id,
                                                     title=the_item.item_name,
                                                     description=the_item.description),
                                        'status': 'pass',
                                        'message': 'item updated'}), 200
                    shoplist_api.logger.error(
                        "item with id: <{0}> on list with id:<{1}> has not been updated ".format(item_id, list_id))
                    return jsonify({'status': 'fail', 'message': 'item not updated'}), 200
                shoplist_api.logger.error("list with id:<%s> does not exist" % list_id)
                return jsonify({'status': 'fail', 'message': 'list does not exist'}), 200
            shoplist_api.logger.error("unknown user id: <%s> " % user_id)
            abort(401)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401


@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>', methods=['DELETE'])
@login_required
def delete_item_from_list(list_id, item_id):
    """
    This endpoint will delete an item on given list
    :param list_id:
    :param item_id:
    :return: json response
    """
    token = None
    try:
        # Get the access token from the header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(" ")[1]
        shoplist_api.logger.debug("token: %s " % token)
    except Exception as ex:
        shoplist_api.logger.error(ex.message)
    #
    if token:
        try:
            user_id = models.User.decode_token(token)
            if isinstance(int(user_id), int):
                shoplist_api.logger.debug("decoded token to get user id %s " % user_id)
                the_list = models.List.query.filter_by(list_id=list_id).first()
                if the_list is not None:
                    the_item = models.Item.query.filter_by(list_id=list_id, item_id=item_id).first()
                    if the_item is not None:
                        item_name = the_item.item_name
                        the_item.delete()
                        shoplist_api.logger.debug("item %s has been deleted successfully" % item_name)
                        return jsonify({'status': 'pass', 'message': 'item deleted'})
                    shoplist_api.logger.error(
                        "item with id: <{0}> on list with id:<{1}> has not been deleted ".format(item_id, list_id))
                    return jsonify({'status': 'fail', 'message': 'item not deleted'}), 200
                shoplist_api.logger.error("list with id:<%s> does not exist" % list_id)
                return jsonify({'status': 'fail', 'message': 'list does not exist'}), 200
            shoplist_api.logger.error("unknown user id: <%s> " % user_id)
            abort(401)
        except Exception as ex:
            shoplist_api.logger.error(ex.message)
            return jsonify({'status': 'fail', 'message': ex.message}), 200
    shoplist_api.logger.error("no access token")
    return jsonify({'status': 'fail', 'message': 'no access token'}), 401
# -------------------------------------------------------------------------------------------------



