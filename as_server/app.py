import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
import threading
import time
import random
from common.rsa import generate_rsa_keys, sign, verify

app = Flask(__name__)

clients = {
    'client1': {'id': 'client1', 'public_key': None},
    'client2': {'id': 'client2', 'public_key': None},
    'client3': {'id': 'client3', 'public_key': None},
    'client4': {'id': 'client4', 'public_key': None}
}

v_server = {'id': 'v_server', 'public_key': None}

as_keys = generate_rsa_keys()
as_public_key = as_keys[0]
as_private_key = as_keys[1]

def generate_session_key():
    return ''.join(random.choices('0123456789abcdef', k=16))

def generate_ticket(client_id, session_key, v_server_id):
    ticket = {
        'client_id': client_id,
        'session_key': session_key,
        'v_server_id': v_server_id,
        'timestamp': int(time.time()),
        'expires': int(time.time()) + 3600
    }
    ticket_str = str(ticket)
    ticket_signature = sign(ticket_str, as_private_key)
    return {'ticket': ticket, 'signature': ticket_signature}

def generate_certificate(entity_id, public_key):
    certificate = {
        'entity_id': entity_id,
        'public_key': public_key,
        'timestamp': int(time.time()),
        'expires': int(time.time()) + 86400,
        'issuer': 'AS_SERVER'
    }
    cert_str = str(certificate)
    cert_signature = sign(cert_str, as_private_key)
    return {'certificate': certificate, 'signature': cert_signature}

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    client_id = data.get('client_id')
    
    if client_id not in clients:
        return jsonify({'status': 'error', 'message': 'Invalid client ID'}), 400
    
    session_key = generate_session_key()
    ticket = generate_ticket(client_id, session_key, 'v_server')
    
    client_cert = generate_certificate(client_id, clients[client_id]['public_key'])
    v_server_cert = generate_certificate('v_server', v_server['public_key'])
    
    return jsonify({
        'status': 'success',
        'session_key': session_key,
        'ticket': ticket,
        'client_certificate': client_cert,
        'v_server_certificate': v_server_cert
    })

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    entity_id = data.get('entity_id')
    public_key = data.get('public_key')
    
    if entity_id in clients:
        clients[entity_id]['public_key'] = public_key
    elif entity_id == 'v_server':
        v_server['public_key'] = public_key
    else:
        return jsonify({'status': 'error', 'message': 'Invalid entity ID'}), 400
    
    return jsonify({'status': 'success', 'message': 'Registration successful'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)