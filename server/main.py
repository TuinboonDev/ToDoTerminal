from flask import Flask, json, request, jsonify
from dotenv import load_dotenv
from Crypto.Cipher import AES
import datetime
import random
import pyotp
import os

load_dotenv()
app = Flask(__name__)

cipher = AES.new(os.getenv("AES_KEY").encode("utf-8"), AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(b"crazy")
print(ciphertext)

@app.route("/api/note/new", methods=["POST"])
def hello_world():
    print(json.loads(request.data))
    return json.dumps({"success":True}), 201
    
@app.route("/api/note/get", methods=["GET"])
def get_note():
    with open("notes.json", "r") as f:
        return json.loads(f.read())
    
@app.route("/api/users/new", methods=["POST"])
def create_user():
    user_data = json.loads(request.data)
    
    with open("database.json", "r") as f:
        data = json.load(f)
        
        for user in data["users"]:
            if user["email"] == user_data["email"]:
                return json.dumps({"message": "An account with this email already exists."}), 409
            if user["username"] == user_data["username"]:
                return json.dumps({"message": "This username is already taken."}), 409
    
    with open("cache.json", "r+") as f:
        cache_data = json.load(f)
        
        x = datetime.datetime.now()            
        id = x.strftime("%H%M")
        
        # TODO: Fix the user ID fields, they are kinda confusing here
        
        otp_secret = pyotp.random_base32()
        
        if not str(id) in cache_data:
            for user in cache_data:
                if int(id) > int(user["id"]) + 30:
                    cache_data.remove(user)
                    
            user_data["id"] = str(id)
            user_data["otp_secret"] = otp_secret
            cache_data.append(user_data)
            
            f.seek(0)
            json.dump(cache_data, f)
            f.truncate()
            
            totp = pyotp.TOTP(otp_secret)
            uri = totp.provisioning_uri(name="ToDoTerminal", issuer_name="2FA")
            
            return json.dumps({"url": uri, "id": user_data["id"]}), 201
        else:
            return json.dumps({"message": "Account was deleted from cache after 30 minutes of inactivity, please create a new account."}), 410
        
@app.route("/api/users/verify", methods=["POST"])
def verify_account():
    user_data = json.loads(request.data)
    with open("cache.json", "r+") as f:
        cache = json.load(f)
        
        for user in cache:
            if user["id"] == user_data["id"]:
                totp = pyotp.TOTP(user["otp_secret"])
                if totp.verify(user_data["otp_code"]):
                    with open("database.json", "r+") as g:
                        data = json.load(g)
                        
                        data["users"].append({
                            "username": user["username"],
                            "password": user["password"],
                            "email": user["email"],
                            "otp_key": user["otp_secret"]
                        })
                                
                        g.seek(0)
                        json.dump(data, g)
                        g.truncate()
                    
                    cache.remove(user)
                    f.seek(0)
                    json.dump(cache, f)
                    f.truncate()
                    
                    return jsonify({"message": "Verification successful, account created."}), 201
                else:
                    return jsonify({"error": "Invalid OTP"}), 401

if __name__ == "__main__":
    app.run(debug=True)