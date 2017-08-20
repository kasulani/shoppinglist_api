"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
--------------------------------------------------------------------------------------
    Models map to database tables
"""
from app import db


class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(250), unique=True)
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    description = db.Column(db.Text())

    def __init__(self, username, email, firstname="", lastname="", description=""):
        self.username = username
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.description = description

    def __repr__(self):
        return '<User %s>' % self.username


class List(db.Model):
    __tablename__ = 'lists'
    list_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('user.username'))
    user = db.relationship('User', backref=db.backref('users', cascade='delete all'))
    list_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text())

    def __init__(self, list_id, list_name, username, description=""):
        self.list_id = list_id
        self.list_name = list_name
        self.username = username
        self.description = description

    def __repr__(self):
        return '<List %s>' % self.list_name


class Item(db.Model):
    __tablename__ = 'items'
    item_id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey('list.list_id'))
    list = db.relationship('List', backref=db.backref('lists', cascade='delete all'))
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text())
    status = db.Column(db.Boolean)

    def __init__(self, item_id, item_name, list_id, description="", status=False):
        self.item_id = item_id
        self.item_name = item_name
        self.list_id = list_id
        self.description = description
        self.status = status

    def __repr__(self):
        return '<List %s>' % self.item_name
