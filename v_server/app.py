import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template
import threading
import time
from common.rsa import verify

app = Flask(__name__)

clients = {}
as_public_key = None

@app.route('/verify_ticket', methods=['POST'])
def verify_ticket():
    data = request.get_json()
    ticket = data.get('ticket')
    signature = data.get('signature')
    client_cert = data.get('client_certificate')
    
    if not ticket or not signature or not client_cert:
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
    
    ticket_str = str(ticket['ticket'])
    if not verify(ticket_str, ticket['signature'], as_public_key):
        return jsonify({'status': 'error', 'message': 'Invalid ticket signature'}), 401
    
    cert_str = str(client_cert['certificate'])
    if not verify(cert_str, client_cert['signature'], as_public_key):
        return jsonify({'status': 'error', 'message': 'Invalid certificate signature'}), 401
    
    if ticket['ticket']['expires'] < int(time.time()):
        return jsonify({'status': 'error', 'message': 'Ticket expired'}), 401
    
    client_id = ticket['ticket']['client_id']
    if client_id not in clients:
        clients[client_id] = {'last_access': int(time.time())}
    else:
        clients[client_id]['last_access'] = int(time.time())
    
    return jsonify({'status': 'success', 'message': 'Ticket verified'})

@app.route('/business', methods=['GET'])
def business():
    return render_template('business.html', clients=clients)

@app.route('/set_as_public_key', methods=['POST'])
def set_as_public_key():
    global as_public_key
    data = request.get_json()
    as_public_key = data.get('as_public_key')
    return jsonify({'status': 'success', 'message': 'AS public key set'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, threaded=True)