from flask import Flask, request, jsonify
from password_manager import add_password, retrieve_password  # Import your existing functions
import json

app = Flask(__name__)

@app.route('/add', methods=['POST'])
def add():
    data = request.get_json()
    service = data['service']
    username = data['username']
    password = data['password']
    add_password(service, username, password)
    return jsonify({'message': 'Password added successfully!'}), 200

@app.route('/retrieve/<service>', methods=['GET'])
def retrieve(service):
    password = retrieve_password(service)
    return jsonify({'password': password}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
