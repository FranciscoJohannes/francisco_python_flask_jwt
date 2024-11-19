import bcrypt
import jwt
from flask import Flask, render_template, request, jsonify, make_response

import jwt_try

app = Flask(__name__)

@app.route('/')
def hello_world():
    return render_template('index.html', message="Hello, World!")

@app.route('/setcookie', methods=['POST'])
def set_cookie():
    # get name from request
    name = request.json.get('name')
    resp = make_response(jsonify({"message": "cookie has been set"}))
    resp.set_cookie('name', name, max_age=60*60*24) # cookie last for 1 day
    return resp

@app.route('/getcookie', methods=['GET'])
def get_cookie():
    # get name from request
    name = request.cookies.get('name')
    if name:
        return jsonify({"name": name})
    else:
        return jsonify({"message": "no name cookie found"}), 404

@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.json.get('password')
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return jsonify({"hashed_password": hashed_password.decode('utf-8')})

@app.route('/verify', methods=['POST'])
def verify_password():
    password = request.json.get('password')
    hashed_password = request.json.get('hashed_password')
    is_verified = bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    return jsonify({"verified": is_verified})


@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if data.username == 'admin' and data.password == 'admin':
        token = jwt_try.generate_token(data)
        return jsonify({"token": token})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/getuser', methods=['GET'])
def get_user():
    token = request.headers.get('authorization')
    if not token:
        return jsonify({"message": "token is missing"}), 401
    try:
        payload = jwt_try.verify_token(token)
        return jsonify({"user": payload})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(debug=True)