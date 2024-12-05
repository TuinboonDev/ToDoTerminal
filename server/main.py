from flask import Flask, json, request

app = Flask(__name__)

@app.route("/api/new", methods=['POST'])
def hello_world():
    print(json.loads(request.data))
    return json.dumps({'success':True}), 201
    
@app.route("/api/get", methods=['GET'])
def get_note():
    with open("notes.json", "r") as f:
        return json.loads(f.read())

if __name__ == "__main__":
    app.run(debug=True)