"""
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
    Even God commands us to write tests. 1 Thessalonians 5:21; Test all things.
"""
from app import shoplist_api, db, models
import unittest
from flask_testing import TestCase
import json
from werkzeug.security import generate_password_hash


class TestShoppingListAPI(TestCase):
    """Tests for the Shopping List API endpoints """
    test_user = "testuser1@gmail.com"
    test_user_password = "testuser123"
    test_list = "test list"
    test_list_desc = "the test description"
    test_item = "test item"
    test_item_desc = "test item description"

    def create_app(self):
        return shoplist_api

    def add_user(self):
        """This is a test user to use during the running of tests"""
        user = models.User(email=self.test_user,
                           password=generate_password_hash(self.test_user_password))
        user.add()

    def add_list(self):
        """This is a list user to use during the running of tests"""
        the_list = models.List(user_id=1,
                               list_name=self.test_list,
                               description=self.test_list_desc)
        the_list.add()

    def add_item(self):
        """This is a test list item to use during the running of tests"""
        item = models.Item(item_name=self.test_item,
                           list_id=1,
                           description=self.test_item_desc)
        item.add()

    def setUp(self):
        db.create_all()
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    # --------------------------- /auth/register endpoint tests --------------------------------------------------------
    def test_01_register_account(self):
        with self.client:
            response = self.client.post('/auth/register',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['username'], "testuser1@gmail.com", msg="username key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "user account created successfully", msg="message key fail")

    def test_02_register_an_existing_account(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            response = self.client.post('/auth/register',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "user already exists", msg="message key fail")

    # --------------------------- /auth/login endpoint tests --------------------------------------------------------

    def test_03_login_with_wrong_credentials(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            response = self.client.post('/auth/login',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser007")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'],
                             "wrong password or username or may be user does't exist", msg="message key fail")

    def test_04_login_with_correct_credentials(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            response = self.client.post('/auth/login',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com",
                                                             password="testuser123")))
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['token'], msg="token key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "login was successful", msg="message key fail")

    # --------------------------- /auth/logout endpoint tests --------------------------------------------------------
    # @unittest.skip("skipping logout test")
    def test_05_logout(self):
        with self.client:
            # you have to be logged in to log out
            self.client.post('/auth/login',
                             content_type='application/json',
                             data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))

            response = self.client.get('/auth/logout', content_type='application/json')
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "logout was successful", msg="message key fail")

    # --------------------------- /auth/reset-password endpoint tests -------------------------------------------
    # @unittest.skip("skipping reset-password with wrong credentials test")
    def test_06_reset_password_with_wrong_credentials(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to reset password
            self.client.post('/auth/login',
                             content_type='application/json',
                             data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))

            # test the reset password endpoint
            response = self.client.post('/auth/reset-password',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com",
                                                             old_password="testuser12300",
                                                             new_password="testuser123")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "wrong username or password or may be user does't exist")

    # @unittest.skip("skipping reset-password with correct test")
    def test_07_reset_password_with_correct_credentials(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to reset password
            self.client.post('/auth/login',
                             content_type='application/json',
                             data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))

            # test the reset password endpoint
            response = self.client.post('/auth/reset-password',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com",
                                                             old_password="testuser123",
                                                             new_password="testuser1234")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['username'], "testuser1@gmail.com", msg="username key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "password was changed successfully", msg="message key fail")

    # --------------------------- /shoppinglists endpoint tests -------------------------------------------
    def test_08_create_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to create a list
            response = self.client.post('/auth/login',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.post('/shoppinglists',
                                        content_type='application/json',
                                        headers=headers,
                                        data=json.dumps(dict(title="house party",
                                                             description="my house party list")))
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['id'], msg="id key fail")
            self.assertEqual(reply['title'], "house party", msg="title key fail")
            self.assertEqual(reply['description'], "my house party list", msg="description key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "list created successfully", msg="message key fail")

    def test_09_view_lists(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.get('/shoppinglists', content_type='application/json', headers=headers)
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['lists'], msg="lists key fail")
            self.assertEqual(reply['count'], "1", msg="count key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "lists found", msg="message key fail")

    def test_10_view_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.get('/shoppinglists/1', content_type='application/json', headers=headers)
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['list'], msg="lists key fail")
            self.assertEqual(reply['count'], "1", msg="count key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "list found", msg="message key fail")

    def test_11_view_a_non_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.get('/shoppinglists/100', content_type='application/json', headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['count'], "0", msg="count key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "list not found", msg="message key fail")

    def test_12_update_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/shoppinglists/1', content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(dict(title="camping list", description="my camping list")))
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['list'], msg="lists key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "list updated", msg="message key fail")

    def test_13_update_a_non_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/shoppinglists/100', content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(dict(title="camping list", description="my camping list")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "list not updated", msg="message key fail")

    # --------------------------- /shoppinglists items endpoint tests ----------------------------------------
    def test_14_add_an_item_to_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        with self.client:
            # you have to be logged in to create a list
            response = self.client.post('/auth/login',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.post('/shoppinglists/1/items',
                                        content_type='application/json',
                                        headers=headers,
                                        data=json.dumps(dict(name="soda",
                                                             description="create of soda")))
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['item_id'], msg="user_id key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "item added to list", msg="message key fail")

    def test_15_add_an_item_to_a_non_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to create a list
            response = self.client.post('/auth/login',
                                        content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.post('/shoppinglists/100/items',
                                        content_type='application/json',
                                        headers=headers,
                                        data=json.dumps(dict(name="soda",
                                                             description="create of soda")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "list does not exist", msg="message key fail")

    def test_16_view_items_on_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        self.add_item()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.get('/shoppinglists/1/items', content_type='application/json', headers=headers)
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['items'], msg="lists key fail")
            self.assertEqual(reply['count'], "1", msg="count key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "items found", msg="message key fail")

    def test_17_view_items_on_a_non_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.get('/shoppinglists/100/items', content_type='application/json', headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "list not found", msg="message key fail")

    def test_18_view_a_single_item_on_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        self.add_item()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.get('/shoppinglists/1/items/1', content_type='application/json', headers=headers)
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['item'], msg="lists key fail")
            self.assertEqual(reply['count'], "1", msg="count key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "item found", msg="message key fail")

    def test_19_view_a_single_non_existing_item_on_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        self.add_item()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.get('/shoppinglists/1/items/100', content_type='application/json', headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['count'], "0", msg="count key fail")
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "item not found", msg="message key fail")

    def test_20_update_an_item_on_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        self.add_item()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/shoppinglists/1/items/1', content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(dict(name="rock boom", description="the energy drink")))
            reply = json.loads(response.data.decode())
            self.assertTrue(reply['item'], msg="item key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "item updated", msg="message key fail")

    def test_21_update_a_non_item_on_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        self.add_item()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/shoppinglists/1/items/100', content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(dict(name="rock boom", description="the energy drink")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "item not updated", msg="message key fail")

    def test_22_update_an_item_on_a_non_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/shoppinglists/100/items/1', content_type='application/json',
                                       headers=headers,
                                       data=json.dumps(dict(name="rock boom", description="the energy drink")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "list does not exist", msg="message key fail")

    # --------------------------- /delete endpoint tests ------------------------------------------------------
    def test_23_delete_an_item_on_a_non_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.delete('/shoppinglists/100/items/1', content_type='application/json',
                                          headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "list does not exist", msg="message key fail")

    def test_24_delete_an_existing_item_on_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        self.add_item()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.delete('/shoppinglists/1/items/1', content_type='application/json',
                                          headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "item deleted", msg="message key fail")

    def test_25_delete_a_non_existing_item_on_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        self.add_item()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.delete('/shoppinglists/1/items/100', content_type='application/json',
                                          headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "item not not found", msg="message key fail")

    def test_26_delete_an_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        self.add_list()
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.delete('/shoppinglists/1', content_type='application/json',
                                          headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "list deleted", msg="message key fail")

    def test_27_delete_a_non_existing_list(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a list
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.delete('/shoppinglists/200', content_type='application/json',
                                          headers=headers)
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "list not deleted", msg="message key fail")

    def test_28_view_existing_user(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a user details
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.get('/users',
                                       content_type='application/json', headers=headers)

            reply = json.loads(response.data.decode())
            self.assertTrue(reply['user'], msg="user key fail")
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "user found", msg="message key fail")

    def test_29_update_an_existing_user(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a user details
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/users',
                                       content_type='application/json', headers=headers,
                                       data=json.dumps(dict(firstname="Test",
                                                            lastname="User",
                                                            description="this is a test user")))

            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "user updated", msg="message key fail")

    def test_30_update_an_existing_user_first_name_only(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a user details
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/users',
                                       content_type='application/json', headers=headers,
                                       data=json.dumps(dict(firstname="Test1")))

            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "user updated", msg="message key fail")

    def test_31_update_an_existing_user_last_name_only(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a user details
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/users',
                                       content_type='application/json', headers=headers,
                                       data=json.dumps(dict(lastname="User1")))

            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "user updated", msg="message key fail")

    def test_32_update_an_existing_user_description_only(self):
        self.add_user()  # add this test user because tearDown drops all table data
        with self.client:
            # you have to be logged in to view a user details
            response = self.client.post('/auth/login', content_type='application/json',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            bearer = "Bearer {}".format(reply['token'])
            headers = {'Authorization': bearer}

            response = self.client.put('/users',
                                       content_type='application/json', headers=headers,
                                       data=json.dumps(dict(description="About user")))

            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "pass", msg="status key fail")
            self.assertEqual(reply['message'], "user updated", msg="message key fail")

    def test_33_calling_any_endpoint_with_wrong_content_type(self):
        with self.client:
            response = self.client.post('/auth/register',
                                        content_type='application/text',
                                        data=json.dumps(dict(username="testuser1@gmail.com", password="testuser123")))
            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "content-type not specified as application/json", msg="message key fail")

    def test_34_calling_any_endpoint_with_no_token(self):
        with self.client:
            response = self.client.get('/users',
                                       content_type='application/json')

            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertEqual(reply['message'], "no access token", msg="message key fail")

    def test_35_calling_any_endpoint_with_wrong_token(self):
        with self.client:
            # you have to be logged in to view a user details
            token = "SDWFiosdf1.spoajsdf.POISDHnkjsaf823rokn"
            bearer = "Bearer {}".format(token)
            headers = {'Authorization': bearer}

            response = self.client.get('/users',
                                       content_type='application/json', headers=headers)

            reply = json.loads(response.data.decode())
            self.assertEqual(reply['status'], "fail", msg="status key fail")
            self.assertTrue(reply['message'], msg="message key fail")

    def test_36_index(self):
        with self.client:
            response = self.client.get('/')
            self.assert_template_used('index.html')
            self.assert200(response, message="failed to display index")

if __name__ == "__main__":
    unittest.main()
