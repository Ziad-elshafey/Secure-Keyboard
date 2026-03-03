# Mock Backend Server for Secure Keyboard

Simple Flask API for demo purposes. Handles encrypted message blind upload and decoy text retrieval.

## Setup

```bash
cd backend
pip install -r requirements.txt
python server.py
```

Server runs on `http://localhost:5000`

## API Endpoints

### 1. Upload Encrypted Message (Blind Upload)
**Endpoint:** `POST /api/upload`

**Request:**
```json
{
  "ciphertext": "base64_encoded_encrypted_data"
}
```

**Response:**
```json
{
  "success": true,
  "messageId": "msg_abc123def456",
  "decoyText": "I'm going to the grocery store"
}
```

### 2. Retrieve Encrypted Message (by Decoy Text)
**Endpoint:** `POST /api/retrieve`

**Request:**
```json
{
  "decoyText": "I'm going to the grocery store"
}
```

**Response:**
```json
{
  "success": true,
  "messageId": "msg_abc123def456",
  "ciphertext": "base64_encoded_encrypted_data"
}
```

### 3. Health Check
**Endpoint:** `GET /api/health`

**Response:**
```json
{
  "status": "online",
  "messages_stored": 5
}
```

### 4. Debug - View All Messages (Demo Only)
**Endpoint:** `GET /api/debug/messages`

**Response:**
```json
{
  "I'm going to the grocery store": {
    "messageId": "msg_abc123",
    "ciphertext": "yX7kP2JmQsT...",
    "timestamp": "2026-02-03 15:45:23.123456"
  }
}
```

## How It Works

1. **Sender's keyboard:**
   - User types message
   - Keyboard compresses + encrypts it
   - Sends encrypted data to `/api/upload`
   - Server returns random decoy text
   - Keyboard replaces input field with decoy text

2. **Receiver sees decoy text on WhatsApp/Signal/etc:**
   - Copies decoy text from message
   - Pastes into their keyboard
   - Keyboard sends decoy text to `/api/retrieve`
   - Server returns encrypted data
   - Keyboard decrypts + decompresses to get original message

## Demo Flow

```
Sender's Phone:
"Meeting at 9pm" 
    ↓ (keyboard encrypt+compress)
"yX7kP2JmQsT...==" 
    ↓ (POST /api/upload)
Server returns: "Going to the grocery store"
    ↓ (keyboard replaces input)
Paste in WhatsApp: "Going to the grocery store"

WhatsApp Message: "Going to the grocery store"
    ↓
Receiver's Phone:
Copy from WhatsApp: "Going to the grocery store"
    ↓ (paste into keyboard)
Keyboard sends to /api/retrieve
    ↓
Server returns: "yX7kP2JmQsT...=="
    ↓ (keyboard decrypt+decompress)
"Meeting at 9pm"
```

## Storage

- Uses **in-memory dictionary** (resets on server restart)
- Each decoy text maps to one encrypted message
- For production: use database (PostgreSQL, MongoDB, etc.)

## Security Notes

- ⚠️ This is **demo only** - not production ready
- Server stores encrypted data but can't read it (no key)
- Decoy texts are randomly assigned
- In production: add authentication, rate limiting, database persistence
