import datetime
import os

import jwt

JWT_SECRET_KEY = "superjwtsecret"


# Function to generate a JWT
def generate_token(data):
    # Define the token payload
    payload = {
        "user_id": data.get("user_id"),
        "role": data.get("role"),
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30),  #
        "iat": datetime.datetime.now(datetime.UTC),  # Issued at
        "sub": "authentication"
    }

    # Encode the payload to create the token
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY", ""), algorithm="HS256")
    return token


data = {
    "user_id": 1,
    "role": "admin"
}

token = create_jwt(data)
print(token)


def verify_token(token):
    # decode the token to get the payload
    try:
        payload = jwt.decode(token, os.getenv("JWT_SECRET_KEY", ""), algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return "Token has expired!"
    except jwt.InvalidTokenError:
        return "Invalid Token!"


payload = verify_token(token)
print(payload)
