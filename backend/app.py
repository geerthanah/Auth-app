from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "secret123")

mongo = PyMongo(app)
db = mongo.db
users_collection = db.users  # Mongo auto-creates collection

# JWT decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = users_collection.find_one({"email": data["email"]})
            if not current_user:
                return jsonify({"message": "User not found!"}), 401
        except:
            return jsonify({"message": "Token is invalid!"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Signup
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    if users_collection.find_one({"email": data["email"]}):
        return jsonify({"message": "User already exists"}), 400
    hashed_pw = generate_password_hash(data["password"], method="sha256")
    users_collection.insert_one({
        "first_name": data["first_name"],
        "last_name": data["last_name"],
        "email": data["email"],
        "password": hashed_pw
    })
    return jsonify({"message": "User created successfully"}), 201

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = users_collection.find_one({"email": data["email"]})
    if not user or not check_password_hash(user["password"], data["password"]):
        return jsonify({"message": "Invalid email or password"}), 401
    token = jwt.encode({
        "email": user["email"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"token": token, "first_name": user["first_name"]}), 200

# Dashboard
@app.route("/dashboard", methods=["GET"])
@token_required
def dashboard(current_user):
    return jsonify({"message": f"Welcome {current_user['first_name']}!"})

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
