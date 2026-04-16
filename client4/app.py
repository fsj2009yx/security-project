import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template, session
import requests
import threading
from common.rsa import generate_rsa_keys, encrypt, decrypt, sign, verify
from common.packet import pack, unpack

app = Flask(__name__)
app.secret_key = 'client_secret_key'

client_id = 'client4'
client_keys = generate_rsa_keys()
client_public_key = client_keys[0]
client_private_key = client_keys[1]

as_server_url = 'http://localhost:5000'
v_server_url = 'http://localhost:5001'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    response = requests.post(f'{as_server_url}/authenticate', json={'client_id': client_id})
    if response.status_code == 200:
        data = response.json()
        session['session_key'] = data['session_key']
        session['ticket'] = data['ticket']
        session['client_certificate'] = data['client_certificate']
        session['v_server_certificate'] = data['v_server_certificate']
        return jsonify({'status': 'success', 'message': 'Authentication successful'})
    else:
        return jsonify({'status': 'error', 'message': 'Authentication failed'}), 401

@app.route('/verify_ticket', methods=['POST'])
def verify_ticket():
    if 'ticket' not in session or 'client_certificate' not in session:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
    
    response = requests.post(f'{v_server_url}/verify_ticket', json={
        'ticket': session['ticket'],
        'client_certificate': session['client_certificate']
    })
    
    if response.status_code == 200:
        return jsonify({'status': 'success', 'message': 'Ticket verified'})
    else:
        return jsonify({'status': 'error', 'message': 'Ticket verification failed'}), 401

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    message = data.get('message')
    
    if 'session_key' not in session:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
    
    encrypted_message = encrypt(message, client_public_key)
    signature = sign(message, client_private_key)
    
    return jsonify({
        'status': 'success',
        'message': message,
        'encrypted_message': encrypted_message,
        'signature': signature
    })

@app.route('/verify_message', methods=['POST'])
def verify_message():
    data = request.get_json()
    message = data.get('message')
    signature = data.get('signature')
    
    is_verified = verify(message, signature, client_public_key)
    
    return jsonify({
        'status': 'success',
        'message': message,
        'is_verified': is_verified
    })

@app.route('/business')
def business():
    if 'ticket' not in session:
        return render_template('error.html', message='Not authenticated')
    
    response = requests.get(f'{v_server_url}/business')
    return response.text

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, threaded=True)