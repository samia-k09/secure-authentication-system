from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
import jwt
import datetime

app = Flask(__name__)

# Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "secure-secret-key-change-this"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# Create database
with app.app_context():
    db.create_all()


# JWT authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"message": "Token is missing"}), 401

        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]

            data = jwt.decode(
                token,
                app.config["SECRET_KEY"],
                algorithms=["HS256"]
            )

            current_user = User.query.get(data["user_id"])

        except Exception:
            return jsonify({"message": "Invalid or expired token"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# Home
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Secure Authentication API is running"
    })


# Register
@app.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({
            "message": "Username, email and password are required"
        }), 400

    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()

    if existing_user:
        return jsonify({
            "message": "Username or email already exists"
        }), 409

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    new_user = User(
        username=username,
        email=email,
        password=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "User registered successfully"
    }), 201


# Login
@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(
        user.password, password
    ):
        return jsonify({
            "message": "Invalid email or password"
        }), 401

    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.datetime.utcnow()
            + datetime.timedelta(hours=1)
        },
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

    return jsonify({
        "message": "Login successful",
        "token": token
    })


# Protected profile
@app.route("/profile", methods=["GET"])
@token_required
def profile(current_user):

    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email
    })


if __name__ == "__main__":
    app.run(debug=True)