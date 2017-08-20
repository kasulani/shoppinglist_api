"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
----------------------------------------------------------------------------------------------
    Endpoints here
"""
from app import shoplist_api
from flask_httpauth import HTTPTokenAuth
auth = HTTPTokenAuth(scheme='Token')


@shoplist_api.route('/auth/register')
def register():
    pass


@shoplist_api.route('/auth/login')
def login():
    pass


@shoplist_api.route('/auth/logout')
def logout():
    pass


@shoplist_api.route('/auth/reset-password')
def reset_password():
    pass
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



