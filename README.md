# Shopping List API
[![Build Status](https://travis-ci.org/kasulani/shoppinglist_api.svg?branch=master)](https://travis-ci.org/kasulani/shoppinglist_api)
[![Coverage Status](https://coveralls.io/repos/github/kasulani/shoppinglist_api/badge.svg?branch=master)](https://coveralls.io/github/kasulani/shoppinglist_api?branch=master)
[![Code Climate](https://codeclimate.com/github/kasulani/shoppinglist_api.svg)](https://codeclimate.com/github/kasulani/shoppinglist_api)
## About
This is an API for a shopping list application that allows users to record and share things they want
to spend money on and keep track of their shopping lists.
## Goal
The goal of this project is to provide a uniform API for both web and mobile frontend shopping list applications.
## Features
With this API;
- You can create a user account - Registration
- You can login and log out - Authorization and Authentication
- You can create, view, update, and delete a shopping list in your user account
- You can create, view, update, and delete an item in your shopping list under your account
## API Documentation
Documentation for this API can be found at http://127.0.0.1:5000, when you run the application locally.
## Tools
Tools used during the development of this API are;
- [Swagger](https://swagger.io/) - this is a tool for documenting the API
- [jwt](https://jwt.io) - JWT is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object
- [Flask](http://flask.pocoo.org/) - this is a python micro-framework
- [Postgresql](https://www.postgresql.org/) - this is a database server
## Requirements
- Python 2.7.1x+. preferably use Python 3.x.x+
## Tests
Even God commands us to run tests: 1 Thessalonians 5:21; "Test all things."
So to run tests, go to your command line prompt and execute the following command
```sh
   $ cd shopping_list_app/
   $ nosetest --with-coverage test_shoplist.py
```
## Running the application
To run this application on a linux box, execute the following command.
```sh
    $ cd shopping_list_api
    $ virtualenv virtenv
    $ source virtenv/bin/activate
    $ pip install -r requirements.txt
    $ python run.py db init
    $ python run.py db migrate
    $ python run.py db upgrade
    $ nohup python run.py runserver > logs/shop.log 2>&1>> logs/shop.log & disown
```
## Endpoints to create a user account and login into the application
HTTP Method|End point | Public Access|Action
-----------|----------|--------------|------
POST | /auth/register | True | Create an account
POST | /auth/login | True | Login a user
POST | /auth/logout | False | Logout a user
POST | /auth/reset-password | False | Reset a user password
GET | /user | False | Returns details of a logged in user
PUT | /user | False | Updates details of a logged in user
## Endpoints to create, update, view and delete a shopping list
HTTP Method|End point | Public Access|Action
-----------|----------|--------------|------
POST | /shoppinglists | False | Create a shopping list
GET | /shoppinglists | False | View all shopping lists
GET | /shoppinglists/id | False | View details of a shopping list
PUT | /shoppinglists/id | False | Updates a shopping list with a given id
DELETE | /shoppinglists/id | False | Deletes a shopping list with a given id
## Endpoints to create, update, view and delete a shopping list item
HTTP Method|End point | Public Access|Action
-----------|----------|--------------|------
GET | /shoppinglists/id/items | False | View Items of a given list id
GET | /shoppinglists/id/items/<item_id> | False | View details of a particular item on a given list id
POST | /shoppinglists/id/items | False | Add an Item to a shopping list
PUT | /shoppinglists/id/items/<item_id> | False | Update a shopping list item on a given list
DELETE | /shoppinglists/id/items/<item_id> | False | Delete a shopping list item from a given list


