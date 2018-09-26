__author__ = "Timothy MacDonald"
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from game_lobby.models import User, Game, BanList
from game_lobby import app, db
import uuid
import re
import logging
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from game_lobby.settings import PASSWORD_LENGTH

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route("/")

@app.route("/get_my_ip", methods=["GET"])
@token_required
def get_my_ip(current_user):
    return jsonify({'ip': request.remote_addr}), 200

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'You do not have permission to perform that function'}),401
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        user_data['email'] = user.email
        output.append(user_data)
    return jsonify({'users':output}),200

@app.route('/user', methods=['POST'])
def create_user():
    ban = BanList.query.filter_by(ip=request.remote_addr).first()
    if ban:
        if (ban.count > 0) and (datetime.timedelta(ban.last_access_date,dattime.datetime.utcnow()).total_seconds() < 300 ):
            ban.count =+ 1
            ban.last_access_date = datetime.datetime.utcnow()
            db.session.commit()
            return jsonify({'message' : 'Too many creation attempts'}),400
    data = request.get_json()
    print (data)
    if  len(data['password']) < PASSWORD_LENGTH:
        logging.debug('New user %s create failed, password too short', data['name'])
        return jsonify({'message': 'Password too short'}), 400

    try:
        re.match('\w*\@\w*\.\w*', data['email'])
    except:
        logging.debug('%s is not a valid e-mail address', data['email'])
        return jsonify({'message': 'Invalid e-mail address'}), 400
    try:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), name=data['name'], email=data['email'], password=hashed_password, admin=False)
        db.session.add(new_user)
        if ban:
            ban.count = + 1
            ban.last_access_date = datetime.datetime.utcnow()
        else:
            new_ban = BanList(ip=request.remote_addr, count=1)
        db.session.commit()
    except:
        logging.debug('User Create Failed: %s %s', data['name'], data['email'])
        return jsonify({'message': 'User Create Failed, name and email must not be registered already'}), 500
    return jsonify({'message': 'OK'}), 200

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'You do not have permission to perform that function'})
    user = User.query.filter_by(public_id=public_id).first()
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin
    user_data['email'] = user.email

    return jsonify({'user' : user_data}), 200


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'You do not have permission to perform that function'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'That public ID does not exist'}), 400

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'User Promoted'}), 200

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'You do not have permission to perform that function'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'That public ID does not exist'}), 400

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User Deleted'}), 200

@app.route('/login', methods=['GET'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        logging.debug('Login attempt failed.')
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})