# flask imports
import os.path
from flask import Flask, request, jsonify, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import uuid  # for public id

from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_swagger_ui import get_swaggerui_blueprint
from cryptography.fernet import Fernet

# creates Flask object
app = Flask(__name__)
# configuration
app.config['SECRET_KEY'] = 'my secret key'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['UPLOAD_FOLDER'] = '/home/svitlana/Documents/Videos/TestVideo/'

url = 'http://localhost:5000/course/download/%s'
key = b"2EXMFV5CyIW6qAlKPF3gS-Y2Q7No86i0ZE8c3pripJs="
f = Fernet(key)

#'Value is empty !!'
# creates SQLALCHEMY object

db = SQLAlchemy(app)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app-name': "Authentication-Flask-Rest-API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Database ORMs

subscribers = db.Table('subscribers',
    db.Column('user_id', db.Integer, db.ForeignKey('user.user_id')),
    db.Column('course_id', db.Integer, db.ForeignKey('course.course_id'))
)

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))
    course = db.relationship('Course', backref=db.backref('subscribe', lazy='dynamic'), secondary=subscribers)


class Course(db.Model):
    __tablename__ = 'course'
    course_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), unique=True)
    video = db.Column(db.String(100), unique=True)
    description = db.Column(db.String(100), unique=True)


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
            if current_user is None:
                return jsonify({
                    'message': 'Not found User!!'
                }), 401
        except:
            return jsonify({
                'message': 'Access token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/course/subscribe/', methods=['POST'])
@token_required
def subscribe(current_user):
    user_name = current_user.name
    #user_name = request.headers.get('name')
    course_title = request.headers.get('title')

    if not course_title:
        return make_response(
            'Could not verify article title',
            401,
            {'WWW-Authenticate': 'Basic realm ="Enter title !!"'}
        )
    user = User.query.filter_by(name=user_name).first()
    course = Course.query.filter_by(title=course_title).first()

    if not course:
        return make_response('Course do not exist!', 401)

    try:
        course.subscribe.append(user)
        db.session.commit()
        return jsonify({
            'massage': 'Subscription was successfully made!'
        }), 201
    except:
        return jsonify({
            'message': 'Subscription failed!'
        }), 401



@app.route('/course/unsubscribe/', methods=['POST'])   #current_user
@token_required
def unsubscribe(current_user):
    user_name = current_user.name
    #user_name = request.headers.get('name')
    course_title = request.headers.get('title')

    if not course_title:
        return make_response(
            'Could not verify course title',
            401,
            {'WWW-Authenticate': 'Basic realm ="Enter title !!"'}
        )
    user = User.query.filter_by(name=user_name).first()
    course = Course.query.filter_by(title=course_title).first()

    if not course:
        return make_response(
            'Course do not exist!',
            401
        )
    try:
        course.subscribe = list(course.subscribe)
        course.subscribe.remove(user)
        db.session.commit()
        return jsonify({
            'massage': 'User has successfully unsubscribed!'
        }), 201
    except:
        return jsonify({
            'message': 'Unsubscribed failed!'
        }), 401


@app.route('/course/get/', methods=['GET'])
@token_required
def get_all_course(current_user):
    courses = Course.query.all()
  # converting the query objects
  # to list of jsons
    output = []
    for course in courses:
      # appending the user data json
      # to the response list
        output.append({
            'id': course.course_id,
            'course_title': course.title,
            'course_video': course.video,
            'course_description': course.description,
            'subscribers': [{'name': user.name,
                             'email': user.email,
                             'public_id': user.public_id} for user in course.subscribe]
        })

    return jsonify({'course': output})



@app.route('/course/download/<string:filename>', methods=['GET'])
def download_course(filename):
    link = url % (filename)
    course = Course.query.filter_by(video=link).first()
    if not course:
        return make_response('Course does not exist !!', 404)

    #@token_required
    def get_file():   #  if need check token, you need uncomment @token_required, and get_file(current_user)
        sfd = ''
        user = User.query.filter_by(name='Igor').first()
        if course in user.course:
            file_key = bytes(filename, 'utf-8')

            file_name = f.decrypt(file_key)
            file = str(file_name, 'utf-8')

            if os.path.exists(f'/home/svitlana/Documents/Videos/TestVideo/{file}'):
                sfd = send_from_directory(app.config['UPLOAD_FOLDER'], file, as_attachment=True)
                course.video = None
                db.session.commit()
            else:
                return make_response(
                    'File do not exist in the catalog!',
                    401,
                    {'WWW-Authenticate': 'Basic realm ="Error with file!!"'}
                )

        else:
            return make_response('User does not subscribe this course!!', 404)
        return sfd

    return get_file()



@app.route('/course/add/', methods=['POST'])
@token_required
def add_course(current_user):

    data = request.headers
    course_title = data.get('title')
    course_description = data.get('description')
    course_video = data.get('video')

    course_video_byte = bytes(course_video, 'utf-8')

    link_byte = f.encrypt(course_video_byte)
    link = str(link_byte, 'utf-8')

    courses = Course.query\
        .filter_by(title=course_title)\
        .first()

    if not courses:
        course = Course(
            title=course_title,
            video=(url % (link)),
            description=course_description
        )
        db.session.add(course)
        db.session.commit()
        return make_response('Course has successfully add !!', 201)
    else:
        return make_response('This course already exists !!', 400)



@app.route('/course/delete/', methods=['DELETE'])
@token_required
def delete_course(current_user):
    data = request.headers
    course_title = data.get('title')

    if not course_title:
        return make_response('Title is empty !!', 400)

    course = Course.query \
        .filter_by(title=course_title) \
        .first()

    if not course:
        return make_response('Course does not exist !!', 404)
    else:
        # delete course
        db.session.delete(course)
        db.session.commit()
        # returns 202 if user deleted
        return make_response('Course was successfully deleted !!', 202)


@app.route('/course/edit/', methods=['PUT'])
@token_required
def edit_course(current_user):
    data = request.headers

    course_title = data.get('title')
    course_description = data.get('description')
    course_video = data.get('video')
    course_id = data.get('id')

    course = Course.query\
        .filter_by(course_id=course_id) \
        .first()

    if not course:
        return make_response('Course does not exist !!', 404)
    else:
        course_video_byte = bytes(course_video, 'utf-8')
        link_byte = f.encrypt(course_video_byte)
        link = str(link_byte, 'utf-8')

        course.title = course_title
        course.description = course_description
        course.video = (url % (link))

        db.session.commit()
        # returns 202 if user edit
        return make_response('Course was successfully edit !!', 202)




@app.route('/users/refresh_token/', methods=['POST'])
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
                'exp': datetime.utcnow() + timedelta(minutes=8)
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


@app.route('/users/delete/', methods=['DELETE'])
@token_required
def delete_user(current_user):
    # creates a dictionary of the form data
    #data = request.form
    #data = request.headers
    # gets email
    user_id = current_user.public_id

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
        return make_response('User was successfully deleted !!', 200)


@app.route('/users/edit/', methods=['PUT'])
@token_required
def edit_user(current_user):
    data = request.headers

    user_id = current_user.public_id
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    user = User.query \
        .filter_by(public_id=user_id) \
        .first()

    if not user:
        return make_response('User does not exist !!', 404)
    else:
        user.name = name
        user.email = email
        user.password = generate_password_hash(password)
        db.session.commit()
        # returns 202 if user edit
        return make_response('User was successfully edit !!', 202)


@app.route('/users/me/', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({'current_user': [{
        'name': current_user.name,
        'email': current_user.email,
        'public_id': current_user.public_id,
        'subscribe': [{'course_title': course.title,
                       'video': course.video,
                       'description': course.description} for course in current_user.course]
    }]})


@app.route('/users/user/', methods=['GET'])
@token_required
def get_user(current_user):

    data = request.headers

    user_id = data.get('public_id')

    user = User.query \
        .filter_by(public_id=user_id) \
        .first()

    if not user_id:
        return make_response(
            'ID is missing !!',
            401,
            {'WWW-Authenticate': 'Basic realm ="Id is missing !!"'}
        )
    if not user:
        return make_response(
            'Could not find user !!',
            401,
            {'WWW-Authenticate': 'Basic realm ="Could not find user !!"'}
        )

    if user_id == user.public_id:
        return jsonify({'users': [{
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email,
            'subscribe': [{'course_title': course.title,
                           'video': course.video,
                           'description': course.description} for course in user.course]
        }]})
    return jsonify({
                'message': 'ID is invalid !!'
            }), 401


# User Database Route
# this route sends back list of users users
@app.route('/users/get/', methods=['GET'])
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
            'email': user.email,
            'subscribe': [{'course_title': course.title,
                           'video': course.video,
                           'description': course.description} for course in user.course]
        })

    return jsonify({'users': output})


# route for loging user in
@app.route('/users/login/', methods=['POST'])
def login():

# creates dictionary of form data
# data = request.form
    data = request.headers

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
            'exp': datetime.utcnow() + timedelta(minutes=8)
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
@app.route('/users/signup/', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    # data = request.form
    data = request.headers

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
