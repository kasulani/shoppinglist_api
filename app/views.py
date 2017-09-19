"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
----------------------------------------------------------------------------------------------
    Endpoints here
"""
from app import shoplist_api, login_manager
from app import models, utility
from flask import request, abort, jsonify, render_template
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


@shoplist_api.route('/', methods=['GET'])
def index():
    """
    This endpoint will return the API documentation
    :return:
    """
    return render_template('index.html')


@shoplist_api.route('/auth/register', methods=['POST'])
@utility.validate_content_type
def register():
    """
    This endpoint will create a user account
    :return: json response
    """
    data = request.json
    shoplist_api.logger.debug("/auth/register: incoming request data %s " % data)
    if 'username' in data and 'password' in data:
        # check if the user exists in the db
        user = models.User.query.filter_by(email=data['username']).first()
        if user is None:
            # create user in the database
            user = models.User(email=data['username'],
                               password=generate_password_hash(data['password']))
            user.add()
            shoplist_api.logger.debug("created user %s " % user)
            return jsonify({'username': user.email,
                            'status': 'pass',
                            'message': 'user account created successfully'}), 201
        shoplist_api.logger.error("user already exists")
        return jsonify({'status': 'fail', 'message': 'user already exists'}), 200
    shoplist_api.logger.error("bad or missing parameters in json body")
    return jsonify({'status': 'fail', 'message': 'bad or missing parameters in request'}), 400


@shoplist_api.route('/auth/login', methods=['POST'])
@utility.validate_content_type
def login():
    """
    This endpoint will login a user with an account
    :return: json response
    """
    data = request.json
    shoplist_api.logger.debug("/auth/login endpoint: incoming request data %s " % data)
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
                                'message': 'login was successful'}), 201
        shoplist_api.logger.error("wrong password or username or may be user does't exist")
        return jsonify({'status': 'fail',
                        'message': 'wrong password or username or may be user does\'t exist'}), 200
    shoplist_api.logger.error("bad or missing parameters in json body")
    return jsonify({'status': 'fail', 'message': 'bad or missing parameters in request'}), 400


@shoplist_api.route('/auth/logout', methods=['GET'])
#@login_required
def logout():
    """
    This endpoint will logout a user
    :return:
    """
    logout_user()
    return jsonify({'status': 'pass', 'message': 'logout was successful'}), 200


@shoplist_api.route('/auth/reset-password', methods=['POST'])
@utility.validate_content_type
#@login_required
def reset_password():
    """
    This endpoint will reset a password for a given user logged in at the front end
    :return: json response
    """
    data = request.json
    shoplist_api.logger.debug("/auth/reset: incoming request data %s " % data)
    if 'username' in data and 'new_password' in data and 'old_password' in data:
        # locate user and check the old password
        user = models.User.query.filter_by(email=data['username']).first()
        if user and check_password_hash(user.password, data['old_password']):
            user.password = generate_password_hash(data['new_password'])
            user.update()
            return jsonify({'username': user.email,
                            'status': 'pass',
                            'message': 'password was changed successfully'}), 201
        shoplist_api.logger.error("wrong username or password or may be user does't exist")
        return jsonify({'status': 'fail',
                        'message': 'wrong username or password or may be user does\'t exist'}), 200
    shoplist_api.logger.error("bad or missing parameters in json body")
    return jsonify({'status': 'fail', 'message': 'bad or missing parameters in request'}), 400

# -------------------------------------------------------------------------------------------------


@shoplist_api.route('/users', methods=['GET'])
@utility.validate_content_type
@utility.validate_token
#@login_required
def get_user_details():
    """
    This endpoint will return details on a single user
    :return: json response
    """
    user_id = models.User.decode_token(utility.get_token())
    user = models.User.query.filter_by(user_id=user_id).first()
    lists = models.List.query.filter_by(user_id=user_id)
    num_of_items, num_of_lists = 0, 0
    for a_list in lists:  # count items on each list and total them up
        num_of_lists += 1  # increment number of lists by 1 on each iteration
        num_of_items += models.Item.query.filter_by(list_id=a_list.list_id).count()
    if user:
        return jsonify({'user': dict(id=user.user_id,
                                     username=user.email,
                                     firstname=user.firstname,
                                     lastname=user.lastname,
                                     description=user.description,
                                     num_of_lists=num_of_lists,
                                     num_of_items=num_of_items),
                        'status': 'pass',
                        'message': 'user found'}), 201
    shoplist_api.logger.error("user does't exist")
    return jsonify({'status': 'fail', 'message': 'user not found'}), 404


@shoplist_api.route('/users', methods=['PUT'])
@utility.validate_content_type
@utility.validate_token
#@login_required
def update_user():
    """
    This endpoint will update user details such as firstname, lastname, description
    :return: json response
    """
    data = request.json
    shoplist_api.logger.debug("/user: incoming request data %s " % data)
    # get the user id from the token
    user_id = models.User.decode_token(utility.get_token())
    # locate the user whose details are to be updated
    user = models.User.query.filter_by(user_id=user_id).first()
    if user and isinstance(int(user_id), int):
        '''
        Each field is in a try block of it's own to give the api user the ability to update a single field
        independent of the other fields in the User model/table
        '''
        err_count = 0
        # first name
        try:
            user.firstname = data['firstname']
        except Exception as ex:
            user.firstname = ""
            err_count += 1
            shoplist_api.logger.warning(ex.message)
        # last name
        try:
            user.lastname = data['lastname']
        except Exception as ex:
            user.lastname = ""
            err_count += 1
            shoplist_api.logger.warning(ex.message)
        # description
        try:
            user.description = data['description']
        except Exception as ex:
            user.description = ""
            err_count += 1
            shoplist_api.logger.warning(ex.message)
        # update the user
        if err_count == 3:  # this means non of the fields was updated
            return jsonify({'status': 'fail',
                            'message': 'user not updated'}), 200
        user.update()
        return jsonify({'status': 'pass',
                        'message': 'user updated'}), 201
    shoplist_api.logger.error("user does't exist")
    return jsonify({'status': 'fail', 'message': 'user not found'}), 404

# -------------------------------------------------------------------------------------------------


@shoplist_api.route('/shoppinglists', methods=['POST'])
@utility.validate_content_type
@utility.validate_token
#@login_required
def add_a_list():
    """
    This endpoint will create a shopping list for a logged in user
    :return: json response
    """
    data = request.json
    user_id = models.User.decode_token(utility.get_token())
    if 'title' in data:
        try:
            description = data['description']
        except Exception as ex:
            shoplist_api.logger.warning(ex.message)
            description = ""
        # create a list
        the_list = models.List(user_id=int(user_id), list_name=data['title'], description=description)
        the_list.add()
        shoplist_api.logger.debug("created {0} for user:<{1}>".format(the_list, the_list.user_id))
        response = jsonify({'id': the_list.list_id,
                            'title': the_list.list_name,
                            'description': the_list.description,
                            'status': 'pass',
                            'message': 'list created successfully'
                            })
        return response, 201
    shoplist_api.logger.error("title is missing in the data")
    return jsonify({'status': 'fail', 'message': 'title is missing in the data'}), 400


@shoplist_api.route('/shoppinglists', methods=['GET'])
@utility.validate_token
#@login_required
def view_all_lists():
    """
    This endpoint will return all the lists for a logged in user and if the q parameter is provided, it will implement
    a search query based on the list name. Other parameters search as limit and page refine the results for the user of
    the API
    :return:
    """
    user_id = models.User.decode_token(utility.get_token())
    results = []
    # query parameters
    q = request.args.get('q', None)  # this parameter contains the name of the list
    limit = request.args.get('limit', 50)  # limits the number of records to 50 per page (optional)
    page = request.args.get('page', 1)  # page one is default, but page can be passed as an argument (optional)
    if q is not None:
        lists = models.List.query.filter(
            models.List.list_name.like("%" + q.strip() + "%")).\
            filter_by(user_id=user_id).paginate(page, limit, False).items
    else:
        lists = models.List.query.filter_by(user_id=user_id).paginate(page, limit, False).items
    for a_list in lists:
        result = {
            'id': a_list.list_id,
            'title': a_list.list_name,
            'description': a_list.description
        }
        results.append(result)
    if len(results) > 0:
        return jsonify({'lists': results,
                        'count': str(len(results)),
                        'status': 'pass',
                        'message': 'lists found'}), 200
    return jsonify({'count': '0', 'status': 'fail', 'message': 'no lists found'}), 404


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['GET'])
@utility.validate_token
#@login_required
def get_a_list(list_id):
    """
    This endpoint will return a list of a given id
    :param list_id:
    :return: json response
    """
    user_id = models.User.decode_token(utility.get_token())
    a_list = models.List.query.filter_by(list_id=list_id, user_id=user_id).first()
    if a_list is not None:
        shoplist_api.logger.debug("list %s found" % a_list)
        response = jsonify({'list': dict(id=a_list.list_id,
                                         title=a_list.list_name,
                                         description=a_list.description),
                            'count': '1',
                            'status': 'pass',
                            'message': 'list found'})
        return response, 200
    shoplist_api.logger.debug("list with id<%s> not found" % list_id)
    return jsonify({'count': '0', 'status': 'pass', 'message': 'list not found'}), 404


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['PUT'])
@utility.validate_content_type
@utility.validate_token
#@login_required
def update_a_list(list_id):
    """
    This endpoint will update a list of with a given id
    :param list_id:
    :return: json response
    """
    data = request.json
    user_id = models.User.decode_token(utility.get_token())
    the_list = models.List.query.filter_by(list_id=list_id, user_id=user_id).first()
    if the_list is not None and 'title' in data:
        try:
            description = data['description']
        except Exception as ex:
            shoplist_api.logger.warning(ex.message)
            description = ""
        #
        the_list.list_name = data['title']
        the_list.description = description
        the_list.update()
        shoplist_api.logger.debug("list with id: <%s> has been updated " % the_list.list_id)
        response = jsonify({'list': dict(id=the_list.list_id,
                                         title=the_list.list_name,
                                         description=the_list.description),
                            'status': 'pass',
                            'message': 'list updated'})
        return response, 201
    shoplist_api.logger.error("list with id: <%s> has not been updated " % list_id)
    return jsonify({'status': 'fail', 'message': 'list not updated'}), 400


@shoplist_api.route('/shoppinglists/<int:list_id>', methods=['DELETE'])
@utility.validate_token
#@login_required
def delete_a_list(list_id):
    """
    This endpoint will delete a list with a given id
    :param list_id:
    :return: json response
    """
    user_id = models.User.decode_token(utility.get_token())
    the_list = models.List.query.filter_by(list_id=list_id, user_id=user_id).first()
    if the_list is not None:
        the_list.delete()
        shoplist_api.logger.debug("list with id<%s> has been deleted " % list_id)
        return jsonify({'status': 'pass', 'message': 'list deleted'}), 200
    return jsonify({'status': 'fail', 'message': 'list not deleted'}), 404


# -------------------------------------------------------------------------------------------------

@shoplist_api.route('/shoppinglists/<int:list_id>/items', methods=['GET'])
@utility.validate_token
#@login_required
def get_list_items(list_id):
    """
    This endpoint will return items on a given list. The results are paginated and a default limit is set in case one is
    not provided in the request.
    :param list_id:
    :return: json response
    """
    the_list = models.List.query.filter_by(list_id=list_id).first()
    if the_list is not None:  # check if list exists
        shoplist_api.logger.debug("getting items on list: %s " % the_list)
        results = []
        # get parameters
        limit = request.args.get('limit', 50)  # limits the number of records to 50 per page (optional)
        page = request.args.get('page', 1)  # page one is default, but page can be passed as an argument (optional)
        items = models.Item.query.filter_by(list_id=list_id).paginate(page, limit, False).items
        for item in items:
            result = {
                'id': item.item_id,
                'name': item.item_name,
                'description': item.description,
                'status': item.status
            }
            results.append(result)
        if len(results) > 0:
            return jsonify({'items': results,
                            'count': str(len(results)),
                            'status': 'pass',
                            'message': 'items found'}), 200
        return jsonify({'count': '0', 'status': 'fail', 'message': 'items not found'}), 404
    shoplist_api.logger.error("list not found")
    return jsonify({'status': 'fail', 'message': 'list not found'}), 404


@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>', methods=['GET'])
@utility.validate_token
#@login_required
def get_list_item(list_id, item_id):
    """
    This endpoint will return details of a particular item on a given list. It returns details on a single
    item on a shopping list
    :param list_id:
    :param item_id:
    :return: json response
    """
    the_list = models.List.query.filter_by(list_id=list_id).first()
    if the_list is not None:  # check if list exists
        the_item = models.Item.query.filter_by(item_id=item_id).first()  # locate the item
        if the_item is not None:
            result = {
                'id': the_item.item_id,
                'name': the_item.item_name,
                'description': the_item.description,
                'status': the_item.status
            }
            return jsonify({'item': result,
                            'count': "1",
                            'status': 'pass',
                            'message': 'item found'}), 200
        return jsonify({'count': '0', 'status': 'fail', 'message': 'item not found'}), 404
    return jsonify({'status': 'fail', 'message': 'list not found'}), 404


@shoplist_api.route('/shoppinglists/<int:list_id>/items', methods=['POST'])
@utility.validate_content_type
@utility.validate_token
#@login_required
def add_items_list(list_id):
    """
    This endpoint will add items to a given list
    :param list_id:
    :return: json response
    """
    the_list = models.List.query.filter_by(list_id=list_id).first()
    # check to ensure the list exists
    if the_list is not None:
        data = request.json
        if 'name' in data:
            try:
                description = data['description']
            except Exception as ex:
                shoplist_api.logger.warning(ex.message)
                description = ""
            # add an item to the list
            item = models.Item(item_name=data['name'],
                               list_id=list_id,
                               description=description)
            item.add()
            shoplist_api.logger.debug("added {0} to list <{1}>".format(item, list_id))
            return jsonify({'item_id': item.item_id, 'name': item.item_name,
                            'description': item.description,
                            'status': 'pass', 'message': 'item added to list'}), 201
        shoplist_api.logger.error("bad or missing parameters in json body")
        return jsonify({'status': 'fail', 'message': 'bad or missing parameters in request'}), 400
    shoplist_api.logger.error("list <%s> does not exist" % list_id)
    return jsonify({'status': 'fail', 'message': 'list does not exist'}), 404


@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>', methods=['PUT'])
@utility.validate_content_type
@utility.validate_token
#@login_required
def update_list_item(list_id, item_id):
    """
    This endpoint will update a given item on a given list
    :param list_id:
    :param item_id:
    :return: json response
    """
    data = request.json
    the_list = models.List.query.filter_by(list_id=list_id).first()
    if the_list is not None:
        the_item = models.Item.query.filter_by(list_id=list_id, item_id=item_id).first()
        shoplist_api.logger.debug(
            "/shoppinglists/<int:list_id>/items/<int:item_id>: incoming request data %s " % data)
        if the_item is not None and 'name' in data:
            try:
                description = data['description']
            except Exception as ex:
                shoplist_api.logger.warning(ex.message)
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
                            'message': 'item updated'}), 201
        shoplist_api.logger.error(
            "item with id: <{0}> on list with id:<{1}> has not been updated ".format(item_id, list_id))
        return jsonify({'status': 'fail', 'message': 'item not updated'}), 400
    shoplist_api.logger.error("list with id:<%s> does not exist" % list_id)
    return jsonify({'status': 'fail', 'message': 'list does not exist'}), 404


@shoplist_api.route('/shoppinglists/<int:list_id>/items/<int:item_id>', methods=['DELETE'])
@utility.validate_content_type
@utility.validate_token
#@login_required
def delete_item_from_list(list_id, item_id):
    """
    This endpoint will delete an item on given list
    :param list_id:
    :param item_id:
    :return: json response
    """
    the_list = models.List.query.filter_by(list_id=list_id).first()
    if the_list is not None:
        the_item = models.Item.query.filter_by(list_id=list_id, item_id=item_id).first()
        if the_item is not None:
            item_name = the_item.item_name
            the_item.delete()
            shoplist_api.logger.debug("item %s has been deleted successfully" % item_name)
            return jsonify({'status': 'pass', 'message': 'item deleted'}), 200
        shoplist_api.logger.error(
            "item with id: <{0}> on list with id:<{1}> has not been deleted ".format(item_id, list_id))
        return jsonify({'status': 'fail', 'message': 'item not not found'}), 404
    shoplist_api.logger.error("list with id:<%s> does not exist" % list_id)
    return jsonify({'status': 'fail', 'message': 'list does not exist'}), 404
# -------------------------------------------------------------------------------------------------



