"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
--------------------------------------------------------------------------------------
    Models map to database tables
"""
from app import db, shoplist_api
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)


class Item(db.Model):
    __tablename__ = 'items'
    item_id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey('lists.list_id'))
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text())
    status = db.Column(db.Boolean)

    def __init__(self, item_id, item_name, list_id, description="", status=False):
        self.item_id = item_id
        self.item_name = item_name
        self.list_id = list_id
        self.description = description
        self.status = status

    def add(self):
        """
        This method adds a new record to the database
        :return:
        """
        db.session.add(self)
        db.session.commit()

    def delete(self):
        """
        This method deletes a record from the database
        :return:
        """
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<List %s>' % self.item_name


class List(db.Model):
    __tablename__ = 'lists'
    list_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('users.username'))
    list_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text())
    # items = db.relationship(Item, backref='List', cascade='delete, all')

    def __init__(self, list_id, list_name, username, description=""):
        self.list_id = list_id
        self.list_name = list_name
        self.username = username
        self.description = description

    def add(self):
        """
        This method adds a new record to the database
        :return:
        """
        db.session.add(self)
        db.session.commit()

    def delete(self):
        """
        This method deletes a record from the database
        :return:
        """
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<List %s>' % self.list_name


class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(250))
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    description = db.Column(db.Text())
    # lists = db.relationship(List, backref='User', cascade='delete,all')

    def __init__(self, username, email, password, firstname="", lastname="", description=""):
        self.username = username
        self.email = email
        self.password = password
        self.firstname = firstname
        self.lastname = lastname
        self.description = description

    def add(self):
        """
        This method add a new record to the database
        :return:
        """
        db.session.add(self)
        db.session.commit()

    def delete(self):
        """
        This method deletes a record from the database
        :return:
        """
        db.session.delete(self)
        db.session.commit()

    def generate_auth_token(self, expiration=600):
        s = Serializer(shoplist_api.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'user': self.username})

    def __repr__(self):
        return '<User %s>' % self.username
