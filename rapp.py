# flask imports
import os.path
import redis
from flask import Flask, request, jsonify, make_response, send_from_directory

import uuid  # for public id
from werkzeug.security import generate_password_hash, check_password_hash

#import zlib
#from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_swagger_ui import get_swaggerui_blueprint

# creates Flask object
app = Flask(__name__)

# configuration
app.config['SECRET_KEY'] = 'my secret key'

# database name
client = redis.Redis(host='127.0.0.1', db=0)
course = redis.Redis(host='127.0.0.1', db=1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['UPLOAD_FOLDER'] = '/home/svitlana/Documents/Videos/TestVideo/'

url = 'http://localhost:5000/course/download/%s'
key = b"2EXMFV5CyIW6qAlKPF3gS-Y2Q7No86i0ZE8c3pripJs="
f = Fernet(key)


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

            for key in sorted(client.keys()):
                if data['public_id'] == str(client.hget(key, 'public_id'), "utf-8"):
                    global current_user
                    current_user = str(key, "utf-8")
                    break
            else:
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


@app.route('/course/download/<string:filename>', methods=['GET'])
def download_course(filename):
    link = url % (filename)

    list_videos = [str(course.hget(key, 'video'), "utf-8") for key in sorted(course.keys())]
    #list_id = [str(key, "utf-8") for key in sorted(course.keys())]

    if link not in list_videos:
        return make_response('Course does not exist !!', 404)

    #@token_required
    def get_file(current_user):   #  if need check token, you need uncomment @token_required, and get_file(current_user)
        link = url % (filename)

        for i in sorted(course.keys()):
            if link == str(course.hget(i, 'video'), 'utf-8'):
                id = str(i, 'utf-8')

        if id in str(client.hget(current_user, 'subscribe'), 'utf-8'):
            file_key = bytes(filename, 'utf-8')
            file_name = f.decrypt(file_key)
            file = str(file_name, 'utf-8')

            if os.path.exists(f'/home/svitlana/Documents/Videos/TestVideo/{file}'):
                sfd = send_from_directory(app.config['UPLOAD_FOLDER'], file, as_attachment=True)

                link_byte = f.encrypt(file_name)
                link = str(link_byte, 'utf-8')

                course.hset(id, 'video', (url % (link)))

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


@app.route('/course/subscribe/', methods=['POST'])
@token_required
def subscribe(current_user):
    course_title = request.headers.get('title')

    list_titles = [str(course.hget(key, 'title'), "utf-8") for key in sorted(course.keys())]

    if not course_title:
        return make_response(
            'Could not verify article title',
            401,
            {'WWW-Authenticate': 'Basic realm ="Enter title !!"'}
        )

    if course_title not in list_titles:
        return make_response('Course do not exist!', 401)

    for i in sorted(course.keys()):
        if course_title == str(course.hget(i, 'title'), "utf-8"):
            cours_id = i

    for id in str(client.hget(current_user, 'subscribe'), "utf-8").split(';'):
        if id == cours_id:
            return jsonify({
                'message': 'This user already subscribe on this course!'
            }), 401

    for id in str(course.hget(cours_id, 'subscribers'), "utf-8").split(';'):
        if id == current_user:
            return jsonify({
                'message': 'This user already subscribe on this course!'
            }), 401

    for key in sorted(course.keys()):
        if course_title == str(course.hget(key, 'title'), "utf-8"):
            client.hset(current_user, 'subscribe', (str(client.hget(current_user, 'subscribe'), "utf-8") + str(key, "utf-8") + ';'))
            course.hset(key, 'subscribers', (str(course.hget(key, 'subscribers'), "utf-8") + str(current_user) + ';'))
            return jsonify({
                'massage': 'Subscription was successfully made!'
            }), 201
            break
    else:
        return jsonify({
            'message': 'Subscription failed!'
        }), 401


@app.route('/course/unsubscribe/', methods=['POST'])
@token_required
def unsubscribe(current_user):
    course_title = request.headers.get('title')

    subscribe = str(client.hget(current_user, 'subscribe'), "utf-8").split(';').copy()
    list_titles = [str(course.hget(key, 'title'), "utf-8") for key in sorted(course.keys())]

    if not course_title:
        return make_response(
            'Could not verify course title',
            401,
            {'WWW-Authenticate': 'Basic realm ="Enter title !!"'}
        )

    if course_title not in list_titles:
        return make_response('Course do not exist!', 401)

    for i in sorted(course.keys()):
        if course_title == str(course.hget(i, 'title'), "utf-8"):
            cours_id = i

    subscribers = str(course.hget(cours_id, 'subscribers'), "utf-8").split(';').copy()

    if current_user not in subscribers:
        return make_response('User do not subscribe on this course!', 401)

    client.hset(current_user, 'subscribe', '')
    course.hset(cours_id, 'subscribers', '')

    for sub in subscribers:
        if sub != current_user:
            course.hset(cours_id, 'subscribers', (str(course.hget(cours_id, 'subscribers'), "utf-8") + sub + ';'))

    for key in subscribe:
        if key != str(cours_id, "utf-8"):
            client.hset(current_user, 'subscribe', (str(client.hget(current_user, 'subscribe'), "utf-8") + key + ';'))
    else:
        return jsonify({
            'massage': 'User has successfully unsubscribed!'
        }), 201

    return jsonify({
        'message': 'Unsubscribed failed!'
    }), 401


@app.route('/course/get/', methods=['GET'])
@token_required
def get_all_course(current_user):
    courses = sorted(course.keys())
    # converting the query objects
    # to list of jsons
    output = []
    for key in courses:
        # appending the user data json
        # to the response list
        output.append({
            'course_id': str(key, "utf-8"),
            'course_title': str(course.hget(key, 'title'), "utf-8"),
            'course_description': str(course.hget(key, 'description'), "utf-8"),
            'course_video': str(course.hget(key, 'video'), "utf-8"),
            'subscribers': [{
                            'public_id': str(client.hget(user, 'public_id'), "utf-8"),
                            'name': str(client.hget(user, 'name'), "utf-8"),
                            'email': str(client.hget(user, 'email'), "utf-8")
                            } for user in str(course.hget(key, 'subscribers'), "utf-8").split(';') if user]
        })
    return jsonify({'course': output})


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

    if sorted(course.keys()):
        for key in sorted(course.keys()):
            if course_title == str(course.hget(key, 'title'), "utf-8") or \
                    course_description == str(course.hget(key, 'description'), "utf-8") or \
                    course_video == str(f.decrypt(bytes(str(course.hget(key, 'video'), "utf-8").split('/')[-1], 'utf-8')), "utf-8"):
                # returns 400 if user already exists
                return make_response('This course already exists !!', 400)
                break
        else:
            # insert course
            course.hmset(len(sorted(course.keys())), {'title': course_title,
                                                      'description': course_description,
                                                      'video': (url % (link)),
                                                      'subscribers': ''})
            return make_response('Course has successfully add !!', 201)
    else:
        course.hmset(len(sorted(course.keys())), {'title': course_title,
                                                  'description': course_description,
                                                  'video': (url % (link)),
                                                  'subscribers': ''})
        return make_response('Course has successfully add !!', 201)


@app.route('/course/delete/', methods=['DELETE'])
@token_required
def delete_course(current_user):
    data = request.headers
    course_title = data.get('title')

    list_titles = [str(course.hget(key, 'title'), "utf-8") for key in sorted(course.keys())]

    #list_id = [str(key, "utf-8") for key in sorted(course.keys())]
    #subscribers = [str(client.hget(key, 'subscribe'), "utf-8").split('; ').copy() for key in sorted(client.keys())]

    user_subscribe = [{'user_id': key,
                       'user_subscribe': str(client.hget(key, 'subscribe'), "utf-8").split(';').copy()}
                      for key in sorted(client.keys())]

    if not course_title:
        return make_response('Title is empty !!', 400)

    if course_title not in list_titles:
        return make_response('Course does not exist !!', 404)
    else:
        # delete course
        for course_id in sorted(course.keys()):
            if course_title == str(course.hget(course_id, 'title'), "utf-8"):
                id = str(course_id, "utf-8")

        for key in sorted(client.keys()):
            client.hset(key, 'subscribe', '')

        for user in user_subscribe:
            for u in user['user_subscribe']:
                if u != id:
                    client.hset(user['user_id'], 'subscribe',
                                (str(client.hget(user['user_id'], 'subscribe'), "utf-8") + u + ';'))

        course.delete(id)
        # returns 202 if user deleted
        return make_response('Course was successfully deleted !!', 202)


@app.route('/course/edit/', methods=['PUT'])
@token_required
def edit_course(current_user):
    data = request.headers

    course_id = data.get('id')
    course_title = data.get('title')
    course_description = data.get('description')
    course_video = data.get('video')

    #list_names = [str(course.hget(key, 'title'), "utf-8") for key in sorted(course.keys())]
    list_id = [str(key, "utf-8") for key in sorted(course.keys())]

    if course_id not in list_id:
        return make_response('Course does not exist !!', 404)
    else:
        course_video_byte = bytes(course_video, 'utf-8')
        link_byte = urlsafe_b64encode(zlib.compress(course_video_byte))
        link = str(link_byte, 'utf-8')

        course.hmset(course_id, {'title': course_title,
                                 'description': course_description,
                                 'video': (url % (link))})
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

        for key in sorted(client.keys()):
            if data['public_id'] == str(client.hget(key, 'public_id'), "utf-8"):
                access_token = jwt.encode({
                    'public_id': str(client.hget(key, 'public_id'), "utf-8"),
                    'exp': datetime.utcnow() + timedelta(minutes=8)
                }, app.config['SECRET_KEY'])
                refresh_token = jwt.encode({
                    'public_id': str(client.hget(key, 'public_id'), "utf-8"),
                    'exp': datetime.utcnow() + timedelta(days=7)
                }, app.config['SECRET_KEY'])

                return make_response(
                    jsonify({'access_token': access_token.decode('UTF-8'), 'refresh_token': refresh_token.decode('UTF-8')}), 200)
    except:
        return jsonify({
            'message': 'Refresh token is invalid !!'
        }), 401


@app.route('/users/delete/', methods=['DELETE'])
@token_required
def delete_user(current_user):
    # creates a dictionary of the form data
    # gets email

    list_id = [str(key, "utf-8") for key in sorted(client.keys())]

    course_subscribers = [{
                'course_id': key,
                'course_subscribers': str(course.hget(key, 'subscribers'), "utf-8").split(';').copy()}
                for key in sorted(course.keys())]

    #user_id = client.hget(current_user, 'public_id').decode("utf-8")

    if current_user not in list_id:
        return make_response('User does not exist !!', 404)
    else:
        # delete user
        for key in sorted(course.keys()):
            course.hset(key, 'subscribers', '')

        for sub in course_subscribers:
            for s in sub['course_subscribers']:
                if s != current_user:
                    course.hset(sub['course_id'], 'subscribers',
                                (str(course.hget(sub['course_id'], 'subscribers'), "utf-8") + s + ';'))

        client.delete(current_user)
        # returns 202 if user deleted
        return make_response('User was successfully deleted !!', 200)


@app.route('/users/edit/', methods=['PUT'])
@token_required
def edit_user(current_user):
    data = request.headers

    list_id = [str(key, "utf-8") for key in sorted(client.keys())]

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if current_user not in list_id:
        return make_response('User does not exist !!', 404)
    else:
        client.hset(current_user, 'name', name)
        client.hset(current_user, 'email', email)
        client.hset(current_user, 'password', generate_password_hash(password))
        # returns 202 if user edit
        return make_response('User was successfully edit !!', 202)


@app.route('/users/me/', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({'current_user': [{
        'name': str(client.hget(current_user, 'name'), "utf-8"),
        'email': str(client.hget(current_user, 'email'), "utf-8"),
        'public_id': str(client.hget(current_user, 'public_id'), "utf-8"),
        'subscribe': [{
                      'course_id': str(cour),
                      'course_title': str(course.hget(cour, 'title'), 'utf-8'),
                      'course_description': str(course.hget(cour, 'description'), 'utf-8'),
                      'course_video': str(course.hget(cour, 'video'), 'utf-8')
                      } for cour in str(client.hget(current_user, 'subscribe'), 'utf-8').split(';') if cour]
    }]})


@app.route('/users/user/', methods=['GET'])
@token_required
def get_user(current_user):
    data = request.headers
    user_id = data.get('public_id')
    public_id = [str(client.hget(key, 'public_id'), "utf-8") for key in sorted(client.keys())]

    if not user_id:
        return make_response(
            'ID is missing !!',
            401,
            {'WWW-Authenticate': 'Basic realm ="Id is missing !!"'}
        )
    if user_id not in public_id:
        return make_response(
            'Could not find user !!',
            401,
            {'WWW-Authenticate': 'Basic realm ="Could not find user !!"'}
        )

    for key in sorted(client.keys()):
        if user_id == str(client.hget(key, 'public_id'), "utf-8"):
            return jsonify({'users': [{
                            'public_id': str(client.hget(key, 'public_id'), "utf-8"),
                            'name': str(client.hget(key, 'name'), "utf-8"),
                            'email': str(client.hget(key, 'email'), "utf-8"),
                            'subscribe': [{
                                          'course_id': str(cour),
                                          'course_title': str(course.hget(cour, 'title'), 'utf-8'),
                                          'course_description': str(course.hget(cour, 'description'), 'utf-8'),
                                          'course_video': str(course.hget(cour, 'video'), 'utf-8')
                                          } for cour in str(client.hget(key, 'subscribe'), 'utf-8').split(';') if cour]
            }]})
            break
    else:
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
    users = sorted(client.keys())
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': str(client.hget(user, 'public_id'), "utf-8"),
            'name': str(client.hget(user, 'name'), "utf-8"),
            'email': str(client.hget(user, 'email'), "utf-8"),
            'subscribe': [{
                          'course_id': str(cour),
                          'course_title': str(course.hget(cour, 'title'), 'utf-8'),
                          'course_description': str(course.hget(cour, 'description'), 'utf-8'),
                          'course_video': str(course.hget(cour, 'video'), 'utf-8')
                          } for cour in str(client.hget(user, 'subscribe'), 'utf-8').split(';') if cour]
             })
    return jsonify({'users': output})


# route for loging user in
@app.route('/users/login/', methods=['POST'])
def login():
    #creates dictionary of form data
    data = request.headers

    if not data or not data.get('email') or not data.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    l = [str(client.hget(key, 'email'), "utf-8") for key in sorted(client.keys())]

    if data.get('email') not in l:
        # returns 404 if user does not exist
        return make_response(
            'Invalid username or password',
            404,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    for key in sorted(client.keys()):
        if data.get('email') == str(client.hget(key, 'email'), "utf-8") and check_password_hash(str(client.hget(key, 'password'), "utf-8"), data.get('password')):
            # generates the JWT Tokens
            access_token = jwt.encode({
                'public_id': str(client.hget(key, 'public_id'), "utf-8"),
                'exp': datetime.utcnow() + timedelta(minutes=8)
            }, app.config['SECRET_KEY'])
            refresh_token = jwt.encode({
                'public_id': str(client.hget(key, 'public_id'), "utf-8"),
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
    #creates a dictionary of the form data
    data = request.headers

    #gets name, email and password
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    # checking for existing user
    if sorted(client.keys()):
        for key in sorted(client.keys()):
            if email == str(client.hget(key, 'email'), "utf-8"):
                # returns 400 if user already exists
                return make_response('User already exists. Please Log in.', 400)
                break
        else:
            # insert user
            client.hmset(len(sorted(client.keys())), {'public_id': str(uuid.uuid4()),
                                                      'name': name,
                                                      'email': email,
                                                      'password': generate_password_hash(password),
                                                      'subscribe': ''})
            return make_response('Successfully registered.', 201)
    else:
        client.hmset(len(sorted(client.keys())), {'public_id': str(uuid.uuid4()),
                                                  'name': name,
                                                  'email': email,
                                                  'password': generate_password_hash(password),
                                                  'subscribe': ''})
        return make_response('Successfully registered.', 201)

if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debuger shell
    # if you hit an error while running the server
    app.run(debug=True)

