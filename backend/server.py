"""
Mock Backend Server for Secure Keyboard Demo
Handles encrypted message blind upload and decoy text retrieval
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
import random

app = Flask(__name__)
CORS(app)

# In-memory storage: decoy_text -> ciphertext mapping
message_store = {}

# Decoy text pool - server generates random decoys
DECOY_TEXTS = [
    "I'm going to the grocery store",
    "What's for dinner tonight?",
    "Did you see the game last night?",
    "Let's grab coffee tomorrow",
    "How's the weather where you are?",
    "I'll be there in 10 minutes",
    "Check out this funny video",
    "See you at the meeting",
    "Don't forget about the deadline",
    "The package arrived today",
    "Can you call me back later?",
    "Just finished work for the day",
    "Looking forward to the weekend",
    "Thanks for your help earlier",
    "Let me know what you think",
]

@app.route('/api/upload', methods=['POST'])
def upload_encrypted_message():
    """
    Blind upload: Receive encrypted ciphertext (in Base64)
    Return randomly assigned decoy text
    
    Request: { "ciphertext": "yX7kP2JmQsT..." }
    Response: { 
        "success": true,
        "messageId": "msg_abc123",
        "decoyText": "I'm going to the grocery store"
    }
    """
    try:
        data = request.get_json()
        ciphertext = data.get('ciphertext')
        
        if not ciphertext:
            return jsonify({
                'success': False,
                'error': 'ciphertext required'
            }), 400
        
        # Generate unique message ID
        message_id = f"msg_{uuid.uuid4().hex[:12]}"
        
        # Randomly pick a decoy text
        decoy_text = random.choice(DECOY_TEXTS)
        
        # Store the encrypted data with decoy mapping
        message_store[decoy_text] = {
            'messageId': message_id,
            'ciphertext': ciphertext,
            'timestamp': str(__import__('datetime').datetime.now())
        }
        
        print(f"[UPLOAD] Message ID: {message_id}")
        print(f"[UPLOAD] Decoy: {decoy_text}")
        print(f"[UPLOAD] Ciphertext length: {len(ciphertext)}")
        
        return jsonify({
            'success': True,
            'messageId': message_id,
            'decoyText': decoy_text
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/retrieve', methods=['POST'])
def retrieve_encrypted_message():
    """
    Retrieve encrypted ciphertext using decoy text
    
    Request: { "decoyText": "I'm going to the grocery store" }
    Response: { 
        "success": true,
        "ciphertext": "yX7kP2JmQsT...",
        "messageId": "msg_abc123"
    }
    """
    try:
        data = request.get_json()
        decoy_text = data.get('decoyText', '').strip()
        
        if not decoy_text:
            return jsonify({
                'success': False,
                'error': 'decoyText required'
            }), 400
        
        # Look up the encrypted data
        if decoy_text not in message_store:
            return jsonify({
                'success': False,
                'error': f'Message not found for decoy: {decoy_text}'
            }), 404
        
        stored = message_store[decoy_text]
        
        print(f"[RETRIEVE] Decoy: {decoy_text}")
        print(f"[RETRIEVE] Message ID: {stored['messageId']}")
        
        return jsonify({
            'success': True,
            'ciphertext': stored['ciphertext'],
            'messageId': stored['messageId']
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'messages_stored': len(message_store)
    }), 200


@app.route('/api/debug/messages', methods=['GET'])
def debug_messages():
    """Debug endpoint - shows all stored messages (DEMO ONLY!)"""
    result = {}
    for decoy, data in message_store.items():
        result[decoy] = {
            'messageId': data['messageId'],
            'ciphertext': data['ciphertext'][:50] + '...',  # Truncate for display
            'timestamp': data['timestamp']
        }
    return jsonify(result), 200


if __name__ == '__main__':
    print("=" * 60)
    print("Secure Keyboard Mock Backend Server")
    print("=" * 60)
    print("Endpoints:")
    print("  POST /api/upload         - Blind upload encrypted message")
    print("  POST /api/retrieve       - Retrieve message by decoy text")
    print("  GET  /api/health         - Health check")
    print("  GET  /api/debug/messages - Show all stored messages (demo)")
    print("=" * 60)
    print("Starting server on http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
