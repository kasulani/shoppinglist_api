"""
    Shopping List API
    Created: 20 - August - 2017
    Author: Emmanuel King Kasulani
    Email: kasulani@gmail.com
"""
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

# Initialise flask application
shoplist_api = Flask(__name__, instance_relative_config=True)
# load the config file in instance folder, don't suppress errors (silent=false)
shoplist_api.config.from_pyfile('config.cfg', silent=False)
# Create ORM object
db = SQLAlchemy(shoplist_api)
# Setup migrations
migrate = Migrate(app=shoplist_api, db=db)
manager = Manager(shoplist_api)
manager.add_command('db', MigrateCommand)
# set logging format
formatter = logging.Formatter("[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")
# set up file handler for the logger
handler = RotatingFileHandler(shoplist_api.config['LOGFILE'], maxBytes=10000000, backupCount=5)
handler.setLevel(shoplist_api.config['LEVEL'])

handler.setFormatter(formatter)
shoplist_api.logger.setLevel(shoplist_api.config['LEVEL'])
shoplist_api.logger.addHandler(handler)
# Create all tables if they are not yet created in the db
try:
    db.create_all()
except Exception as ex:
    shoplist_api.logger.error(ex.message)


from app import views


