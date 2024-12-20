from flask import Flask, json, request, jsonify
from dotenv import load_dotenv
from Crypto.Cipher import AES
import random
import pyotp
import os
import jwt
import base64
import time

load_dotenv()
app = Flask(__name__)

# cipher = AES.new(os.getenv("AES_KEY").encode("utf-8"), AES.MODE_EAX)
# ciphertext, tag = cipher.encrypt_and_digest(b"crazy")
# print(ciphertext)

# TODO: implicit file closing
# TODO: use time instead of datetime for all expiry?

SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_KEY")

def generate_access_token(user_id):
    return jwt.encode(
        {
            "user_id": user_id,
            "exp": int(time.time()) + 300
        },
        SECRET_KEY,
        algorithm="HS256"
    )

def generate_refresh_token(user_id, token_version):
    return jwt.encode(
        {
            "user_id": user_id,
            "exp": int(time.time()) + 604800,
            "token_version": token_version
        },
        REFRESH_SECRET_KEY,
        algorithm="HS256"
    )
    
def verify_token(token, secret):
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.InvalidTokenError:
        return "invalid"
    
@app.route("/api/auth/new", methods=["POST"])
def create_user():
    user_data = request.json
    
    database_file = open("database.json", "r")
    cache_file = open("cache.json", "r+")
    
    database = json.load(database_file)
    cache = json.load(cache_file)
        
    for user in database["users"]:
        if user["email"] == user_data["email"]:
            return json.dumps({"error": "An account with this email already exists."}), 409
        if user["username"] == user_data["username"]:
            return json.dumps({"error": "This username is already taken."}), 409
    
    x = int(time.time())        
    
    # TODO: ig there could be duplicate IDs
    
    id = int(time.time())
    
    # TODO: Fix the user ID fields, they are kinda confusing here
    
    otp_key = pyotp.random_base32()
    
    if not id in database:
        for user in cache:
            if x >= user["expiry"]:
                cache.remove(user)
                
        user_data["expiry"] = x + 1800
        user_data["id"] = str(id)
        user_data["otp_key"] = otp_key
        user_data["purpose"] = "new_account"
        cache.append(user_data)
        
        cache_file.seek(0)
        json.dump(cache, cache_file)
        cache_file.truncate()
        
        totp = pyotp.TOTP(otp_key)
        uri = totp.provisioning_uri(name="ToDoTerminal", issuer_name="2FA")
        
        return json.dumps({"url": uri, "id": str(id)}), 201
    else:
        return json.dumps({"message": "Account was deleted from cache after 30 minutes of inactivity, please create a new account."}), 410
        
@app.route("/api/auth/verify", methods=["POST"])
def verify_account():
    user_data = request.json
    cache_file = open("cache.json", "r+")
    database_file = open("database.json", "r+")

    cache = json.load(cache_file)
    database = json.load(database_file)
        
    for cache_user in cache:
        if cache_user["id"] == user_data["id"]:
            totp = pyotp.TOTP(cache_user["otp_key"])
            if totp.verify(user_data["otp_code"]):
                cache.remove(cache_user)
                    
                cache_file.seek(0)
                json.dump(cache, cache_file)
                cache_file.truncate()
                                        
                id = cache_user["id"]
                        
                match cache_user["purpose"]:
                    case "new_account":   
                        database["users"].append({
                            "username": cache_user["username"],
                            "password": cache_user["password"],
                            "email": cache_user["email"],
                            "otp_key": cache_user["otp_key"],
                            "id": id,
                            "token_version": 0
                        })
                                
                        database_file.seek(0)
                        json.dump(database, database_file)
                        database_file.truncate()
                        
                        access_token = generate_access_token(id)
                        refresh_token = generate_refresh_token(id, 0)
                        
                        return jsonify({"message": "Verification successful, account created.", "access_token": access_token, "refresh_token": refresh_token}), 201
                    
                    case "2fa":
                        access_token = generate_access_token(id)
                        refresh_token = generate_refresh_token(id, cache_user["token_version"])
                
                        return jsonify({"message": "Successfully authorized", "access_token": access_token, "refresh_token": refresh_token}), 200
                    
            else:
                return jsonify({"error": "Invalid OTP"}), 401
    return jsonify({"error": "User not found"}), 404
                            
@app.route("/api/auth/login", methods=["POST"])
def login():
    user_data = request.json
    
    database_file = open("database.json", "r")
    cache_file = open("cache.json", "r+")

    database = json.load(database_file)
    cache = json.load(cache_file)
        
    for user in database["users"]:
        if user["email"] == user_data["email"] and user["password"] == user_data["password"] and user["username"] == user_data["username"]:
            x = int(time.time())

            for user in cache:
                if x >= user["expiry"]:
                    cache.remove(user)

            user["purpose"] = "2fa"
            user["expiry"] = x + 1800

            cache.append(user)
    
            cache_file.seek(0)
            json.dump(cache, cache_file)
            cache_file.truncate()
            
            return json.dumps({"message": "Login successfull please follow with 2fa"}), 200
        
    return json.dumps({"error": "Invalid Credentials"}), 401
        
@app.route("/api/auth/logout", methods=["GET"])
def logout():
    database_file = open("database.json", "r+")
    database = json.load(database_file)

    access_token = request.headers.get("Authorization")
    decoded = verify_token(access_token, SECRET_KEY)
    if decoded == "expired":
        return jsonify({"error": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        
        for user in database["users"]:
            if user["id"] == user_id:
                user["token_version"] += 1
                
                database_file.seek(0)
                json.dump(database, database_file)
                database_file.truncate()
                
                return json.dumps({"message": "Successfully logged out"}), 200
            
    return json.dumps({"error": "User not found"}), 404               

@app.route("/api/auth/refresh", methods=["POST"])
def refresh_token():
    refresh_token = request.headers.get("Authorization")
    decoded = verify_token(refresh_token, REFRESH_SECRET_KEY)

    if decoded == "expired":
        return jsonify({"error": "Refresh token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:
        new_access_token = generate_access_token(decoded["user_id"])
        return jsonify({"access_token": new_access_token}), 200
    
@app.route("/api/notes/get", methods=["GET"])
def get_token():
    access_token = request.headers.get("Authorization")
    decoded = verify_token(access_token, SECRET_KEY)
    if decoded == "expired":
        return jsonify({"error": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"error": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        
        notes_file = open("notes.json", "r")
        notes = json.load(notes_file)
        
        print(notes[user_id]["notes"])
        
        return notes[user_id]["notes"]
    
@app.route("/api/notes/create", methods=["POST"])
def create_note():
    print(json.loads(request.data))
    return json.dumps({"success":True}), 201

@app.route("/api/notes/delete", methods=["GET"])
def delete_token():
    print(json.loads(request.data))
    return json.dumps({"success":True}), 201

if __name__ == "__main__":
    app.run(debug=True)