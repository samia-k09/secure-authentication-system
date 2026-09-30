# Secure Authentication System

A secure backend authentication system developed using Python and Flask. The system provides user registration, password hashing, JWT-based authentication, and protected user profile access.

## Features

- User registration
- Secure password hashing using bcrypt
- User login authentication
- JWT token generation
- Protected API endpoints
- SQLite database for storing user information
- RESTful API architecture

## Technologies Used

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Bcrypt
- PyJWT
- SQLite

## API Endpoints

### GET /
Checks whether the authentication API is running.

### POST /register
Registers a new user.

Example request:

```json
{
    "username": "samia",
    "email": "samia@example.com",
    "password": "123456"
}