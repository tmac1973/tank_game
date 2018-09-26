__author__ = "Timothy MacDonald"
from game_lobby import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    game = db.relationship('Game', backref='gameowner', lazy=True)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}'"

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    members = db.Column(db.Text, nullable=False)
    owner = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    server = db.Column(db.String(50), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    max_num_players = db.Column(db.Integer, nullable=False, default=2)

    def __repr__(self):
        return f"Game('{self.name}', '{self.date_created}', '{self.owner}', '{self.num_players}', '{self.server}', '{self.port}'"

class BanList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    last_access_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    count = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"BanList('{self.last_access_date}', '{self.ip}', '{self.count})'"



