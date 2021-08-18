# flask imports
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid  # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps

# creates Flask object
app = Flask(__name__)
# configuration
app.config['SECRET_KEY'] = 'your secret key'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)


# Database ORMs
class User(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   public_id = db.Column(db.String(50), unique=True)
   name = db.Column(db.String(100))
   email = db.Column(db.String(70), unique=True)
   password = db.Column(db.String(80))


# decorator for verifying the JWT
def token_required(f):
   @wraps(f)
   def decorated(*args, **kwargs):
       access_token = None
       # jwt is passed in the request header
       if 'x-access-token' in request.headers:
           access_token = request.headers['x-access-token']

       # return 401 if token is not passed
       if not access_token:
           return jsonify({'message': 'Access token is missing !!'}), 401

       try:
           # decoding the payload to fetch the stored details
           data = jwt.decode(access_token, app.config['SECRET_KEY'])
           current_user = User.query \
               .filter_by(public_id=data['public_id']) \
               .first()
       except:
           return jsonify({
               'message': 'Access token is invalid !!'
           }), 401
       # returns the current logged in users contex to the routes
       return f(current_user, *args, **kwargs)

   return decorated

@app.route('/user/refresh_token', methods=['POST'])
def refresh_token():
   refresh_token = None

   if 'x-refresh-token' in request.headers:
       refresh_token = request.headers['x-refresh-token']

   if not refresh_token:
       return jsonify({'message': 'Refresh token is missing !!'}), 401

   try:
       # decoding the payload to fetch the stored details
       data = jwt.decode(refresh_token, app.config['SECRET_KEY'])
       user_current = User.query \
           .filter_by(public_id=data['public_id']) \
           .first()
       if user_current.public_id == data['public_id']:
           a_token = jwt.encode({
               'public_id': user_current.public_id,
               'exp': datetime.utcnow() + timedelta(minutes=5)
           }, app.config['SECRET_KEY'])
           r_token = jwt.encode({
               'public_id': user_current.public_id,
               'exp': datetime.utcnow() + timedelta(days=7)
           }, app.config['SECRET_KEY'])

           return make_response(
               jsonify({'access_token': a_token.decode('UTF-8'), 'refresh_token': r_token.decode('UTF-8')}),
               200)
   except:
       return jsonify({
           'message': 'Refresh token is invalid !!'
       }), 401

@app.route('/user/edit_user', methods=['PUT'])
@token_required
def edit_user(current_user):
   data = request.form

   user_id = data.get('public_id')
   name = data.get('name')
   email = data.get('email')

   user = User.query \
       .filter_by(public_id=user_id) \
       .first()

   if not user:
       return make_response('User does not exist !!', 404)
   else:
       user.name = name
       user.email = email
       db.session.commit()
       # returns 202 if user edit
       return make_response('User was successfully edit !!', 202)

@app.route('/user/delete_user', methods=['DELETE'])
@token_required
def delete_user(current_user):
   # creates a dictionary of the form data
   data = request.form
   # gets email
   user_id = data.get('public_id')

   user = User.query \
       .filter_by(public_id=user_id) \
       .first()

   if not user:
       return make_response('User does not exist !!', 404)
   else:
       # delete user
       db.session.delete(user)
       db.session.commit()
       # returns 202 if user deleted
       return make_response('User was successfully deleted !!', 204)

# User Database Route
# this route sends back list of users users
@app.route('/user/get_users', methods=['GET'])
@token_required
def get_all_users(current_user):
   # querying the database
   # for all the entries in it
   users = User.query.all()
   # converting the query objects
   # to list of jsons
   output = []
   for user in users:
       # appending the user data json
       # to the response list
       output.append({
           'public_id': user.public_id,
           'name': user.name,
           'email': user.email
       })

   return jsonify({'users': output})


# route for loging user in
@app.route('/user/login', methods=['POST'])
def login():
   # creates dictionary of form data
   data = request.form

   if not data or not data.get('email') or not data.get('password'):
       # returns 401 if any email or / and password is missing
       return make_response(
           'Could not verify',
           401,
           {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
       )

   user = User.query \
       .filter_by(email=data.get('email')) \
       .first()

   if not user:
       # returns 404 if user does not exist
       return make_response(
           'Invalid username or password',
           404,
           {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
       )

   if check_password_hash(user.password, data.get('password')):
       # generates the JWT Tokens
       access_token = jwt.encode({
           'public_id': user.public_id,
           'exp': datetime.utcnow() + timedelta(minutes=5)
       }, app.config['SECRET_KEY'])
       refresh_token = jwt.encode({
           'public_id': user.public_id,
           'exp': datetime.utcnow() + timedelta(days=7)
       }, app.config['SECRET_KEY'])

       return make_response(jsonify({'access_token': access_token.decode('UTF-8'), 'refresh_token': refresh_token.decode('UTF-8')}), 200)
   # returns 409 if password is wrong
   return make_response(
       'Could not verify',
       400,
       {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
   )


# signup route
@app.route('/user/signup', methods=['POST'])
def signup():
   # creates a dictionary of the form data
   data = request.form

   # gets name, email and password
   name, email = data.get('name'), data.get('email')
   password = data.get('password')

   # checking for existing user
   user = User.query \
       .filter_by(email=email) \
       .first()
   if not user:
       # database ORM object
       user = User(
           public_id=str(uuid.uuid4()),
           name=name,
           email=email,
           password=generate_password_hash(password)
       )
       # insert user
       db.session.add(user)
       db.session.commit()

       return make_response('Successfully registered.', 201)
   else:
       # returns 400 if user already exists
       return make_response('User already exists. Please Log in.', 400)


if __name__ == "__main__":
   # setting debug to True enables hot reload
   # and also provides a debuger shell
   # if you hit an error while running the server
   app.run(debug=True)
