from flask import Flask, json, request, jsonify
from dotenv import load_dotenv
from Crypto.Cipher import AES
from datetime import datetime, timedelta
import random
import pyotp
import os
import jwt

load_dotenv()
app = Flask(__name__)

# cipher = AES.new(os.getenv("AES_KEY").encode("utf-8"), AES.MODE_EAX)
# ciphertext, tag = cipher.encrypt_and_digest(b"crazy")
# print(ciphertext)

# TODO: implicit file closing

SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_KEY")

def generate_access_token(user_id):
    return jwt.encode(
        {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(minutes=5)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

def generate_refresh_token(user_id, token_version):
    return jwt.encode(
        {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(days=1),
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
    
    with open("database.json", "r") as f:
        data = json.load(f)
        
        for user in data["users"]:
            if user["email"] == user_data["email"]:
                return json.dumps({"message": "An account with this email already exists."}), 409
            if user["username"] == user_data["username"]:
                return json.dumps({"message": "This username is already taken."}), 409
    
    with open("cache.json", "r+") as f:
        cache_data = json.load(f)
        
        x = datetime.now()            
        
        # TODO: ig there could be duplicate IDs
        
        id = str(x.strftime("%f%H%M"))
        
        # TODO: Fix the user ID fields, they are kinda confusing here
        
        otp_key = pyotp.random_base32()
        
        if not id in data:
            for user in cache_data:
                if x >= datetime.strptime(user["expiry"], "%a, %d %b %Y %H:%M:%S %Z"):
                    cache_data.remove(user)
                    
            user_data["expiry"] = x + timedelta(minutes=30)
            user_data["id"] = str(id)
            user_data["otp_key"] = otp_key
            user_data["purpose"] = "new_account"
            cache_data.append(user_data)
            
            f.seek(0)
            json.dump(cache_data, f)
            f.truncate()
            
            totp = pyotp.TOTP(otp_key)
            uri = totp.provisioning_uri(name="ToDoTerminal", issuer_name="2FA")
            
            return json.dumps({"url": uri, "id": user_data["id"]}), 201
        else:
            return json.dumps({"message": "Account was deleted from cache after 30 minutes of inactivity, please create a new account."}), 410
        
@app.route("/api/auth/verify", methods=["POST"])
def verify_account():
    user_data = request.json
    with open("cache.json", "r+") as f:
        cache = json.load(f)
        
        for user in cache:
            print(type(user["id"]), type(user_data["id"]))

            print(user["id"], user_data["id"])
            if user["id"] == user_data["id"]:
                totp = pyotp.TOTP(user["otp_key"])
                if totp.verify(user_data["otp_code"]):
                    cache.remove(user)
                    
                    f.seek(0)
                    json.dump(cache, f)
                    f.truncate()
                                        
                    id = user["id"]
                    
                    with open("database.json", "r+") as h:
                        data = json.load(h)
                        
                        for userb in data["users"]:
                            print(userb["id"], user_data["id"])
                            if userb["id"] == user_data["id"]:
                                userb["token_version"] += 1
                                
                                h.seek(0)
                                json.dump(data, h)
                                h.truncate()
                        
                    match user["purpose"]:
                        case "new_account":   
                            with open("database.json", "r+") as g:
                                data = json.load(g)        
                           
                                data["users"].append({
                                    "username": user["username"],
                                    "password": user["password"],
                                    "email": user["email"],
                                    "otp_key": user["otp_key"],
                                    "id": id,
                                    "token_version": 0
                                })
                                        
                                g.seek(0)
                                json.dump(data, g)
                                g.truncate()
                            
                            access_token = generate_access_token(id)
                            refresh_token = generate_refresh_token(id, 0)
                            
                            return jsonify({"message": "Verification successful, account created.", "access_token": access_token, "refresh_token": refresh_token}), 201
                        
                        case "2fa":
                            access_token = generate_access_token(id)
                            refresh_token = generate_refresh_token(id, user["token_version"])
                            
                            return jsonify({"message": "Successfully authorized", "access_token": access_token, "refresh_token": refresh_token}), 200
                    
                else:
                    return jsonify({"error": "Invalid OTP"}), 401
    return jsonify({"error": "User not found"}), 404
                            
@app.route("/api/auth/login", methods=["POST"])
def login():
    user_data = request.json
    
    with open("database.json", "r+") as f:
        data = json.load(f)
        
        for user in data["users"]:
            if user["email"] == user_data["email"] and user["password"] == user_data["password"] and user["username"] == user_data["username"]:
                with open("cache.json", "r+") as f:
                    cache_data = json.load(f)
        
                    x = datetime.now()            
        
                    for user in cache_data:
                        if x >= datetime.strptime(user["expiry"], "%a, %d %b %Y %H:%M:%S %Z"):
                            cache_data.remove(user)

                    user["purpose"] = "2fa"
                    user["expiry"] = x + timedelta(minutes=30)

                    cache_data.append(user)
            
                    f.seek(0)
                    json.dump(cache_data, f)
                    f.truncate()
                return json.dumps({"message": "Login successfull please follow with 2fa"}), 200
            else:
                return json.dumps({"message": "Invalid Credentials"}), 401
                
@app.route("/api/auth/refresh", methods=["POST"])
def refresh_token():
    refresh_token = request.json["refresh_token"]
    decoded = verify_token(refresh_token, REFRESH_SECRET_KEY)

    if decoded == "expired":
        return jsonify({"message": "Refresh token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"message": "Invalid token"}), 401
    else:
        new_access_token = generate_access_token(decoded["user_id"])
        return jsonify({"access_token": new_access_token}), 200
        
@app.route("/api/notes/new", methods=["POST"])
def hello_world():
    print(json.loads(request.data))
    return json.dumps({"success":True}), 201
    
@app.route("/api/notes/get", methods=["GET"])
def get_note():
    access_token = request.headers.get("Authorization").split(" ")[1]
    decoded = verify_token(access_token, SECRET_KEY)
    if decoded == "expired":
        return jsonify({"message": "Access token expired"}), 401
    elif decoded == "invalid":
        return jsonify({"message": "Invalid token"}), 401
    else:    
        user_id = decoded["user_id"]
        
        with open("notes.json", "r") as f:
            return json.loads(f.read())[user_id]["notes"]

if __name__ == "__main__":
    app.run(debug=True)