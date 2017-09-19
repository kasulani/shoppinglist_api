"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
--------------------------------------------------------------------------------------
    Models map to database tables
"""
from app import db, shoplist_api
import jwt
from datetime import datetime, timedelta


class User(db.Model):
    __tablename__ = 'users'
    # username = db.Column(db.String(50), primary_key=True)
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(250))
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    description = db.Column(db.Text())
    user_lists = db.relationship('List', order_by='List.list_id', cascade='delete,all')

    def __init__(self, email, password, firstname="", lastname="", description=""):
        # self.username = username
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

    @staticmethod
    def update():
        """
        This method update a new record to the database
        :return:
        """
        db.session.commit()

    def delete(self):
        """
        This method deletes a record from the database
        :return:
        """
        db.session.delete(self)
        db.session.commit()

    def generate_auth_token(self, expiration=100):
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(minutes=expiration),
                'iat': datetime.utcnow(),
                'sub': self.user_id
            }
            # create the byte string token using the payload and the SECRET key
            jwt_string = jwt.encode(
                payload,
                shoplist_api.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jwt_string
        except Exception as ex:
            return str(ex)

    @staticmethod
    def decode_token(token):
        """Decodes the access token from the Authorization header."""
        try:
            # try to decode the token using our SECRET variable
            payload = jwt.decode(token, shoplist_api.config['SECRET_KEY'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            # the token is expired, return an error string
            return "Expired token. Please login to get a new token"
        except jwt.InvalidTokenError:
            # the token is invalid, return an error string
            return "Invalid token. Please register or login"

    def __repr__(self):
        return '<User: %s>' % self.email


class List(db.Model):
    __tablename__ = 'lists'
    list_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.user_id))
    list_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text())
    list_items = db.relationship('Item', order_by='Item.item_id', cascade='delete, all')

    def __init__(self, list_name, user_id, description=""):
        # self.list_id = list_id
        self.list_name = list_name
        self.user_id = user_id
        self.description = description

    def add(self):
        """
        This method adds a new record to the database
        :return:
        """
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def update():
        """
        This method update a new record to the database
        :return:
        """
        db.session.commit()

    def delete(self):
        """
        This method deletes a record from the database
        :return:
        """
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return '<List: %s>' % self.list_name


class Item(db.Model):
    __tablename__ = 'items'
    item_id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey(List.list_id))
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text())
    status = db.Column(db.Boolean)

    def __init__(self, item_name, list_id, description="", status=False):
        # self.item_id = item_id
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

    @staticmethod
    def update():
        """
        This method update a new record to the database
        :return:
        """
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

