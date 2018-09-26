__author__ = "Timothy MacDonald"
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import logging

logging.basicConfig(filename='game_lobby.log',format='%(asctime)s %(message)s',level=logging.DEBUG)
logging.info('Started Game Lobby')
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lobby.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

from game_lobby import routes