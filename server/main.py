from flask import Flask, json, request
import pyotp
import qrcode
from Crypto.Cipher import AES
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)

cipher = AES.new(os.getenv("AES_KEY").encode('utf-8'), AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(b"crazy")
print(ciphertext)

totp = pyotp.TOTP("BKFRG5NK3PR5IONT6S6Q6KCAF7TJHNWU")
uri = totp.provisioning_uri(name="ToDoTerminal 2FA", issuer_name="ToDoTerminal")

otp_input = input("Enter the OTP: ")

# Verify the OTP
if totp.verify(otp_input):
    print("Authentication successful!")
else:
    print("Invalid OTP.")

@app.route("/api/note/new", methods=['POST'])
def hello_world():
    print(json.loads(request.data))
    return json.dumps({'success':True}), 201
    
@app.route("/api/note/get", methods=['GET'])
def get_note():
    with open("notes.json", "r") as f:
        return json.loads(f.read())
    
@app.route("/api/users/new")
def create_user():
    user_data = json.loads(request.data)
    with open("database.json", "r+") as f:
        data = json.load(f)
        
        for user in data["users"]:
            if user["email"] == user_data["email"]:
                print("An account with this email already exists")
            if user["username"] == user_data["username"]:
                print("This username is already taken")
                
        secret = pyotp.random_base32().secret
                
        data["users"].append({
            "username": user_data["username"],
            "password": user_data["password"],
            "email": user_data["email"],
            "otp_key": secret
        })
        
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="ToDoTerminal", issuer_name="2FA")
                
        f.seek(0)
        json.dump(data, f)
        f.truncate()
        
    return json.dumps({'url': uri}), 201

if __name__ == "__main__":
    app.run(debug=True)