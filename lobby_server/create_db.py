__author__ = "Timothy MacDonald"
from game_lobby import db

db.create_all()

from game_lobby.models import User, Game
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

hashed_password = generate_password_hash('password', method='sha256')
new_user = User(public_id=str(uuid.uuid4()), name='administrator', email='change@this.com', password=hashed_password, admin=True)
db.session.add(new_user)
db.session.commit()