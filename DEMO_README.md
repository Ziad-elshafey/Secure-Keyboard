# Secure Messaging Demo — Quick Reference

This guide ensures successful decryption by avoiding the common "wrong key or tampered data" error.

## Critical: Clear Database Before Each Demo

**Decryption fails when keys are out of sync.** Clear the database before every demo run:

```bash
cd Secure-application/Server
python -c "import sqlite3; c = sqlite3.connect('secure_messaging.db'); cu = c.cursor(); cu.execute('DELETE FROM messages'); cu.execute('DELETE FROM conversations'); cu.execute('DELETE FROM conversation_participants'); cu.execute('DELETE FROM users'); cu.execute('DELETE FROM seeds_vault'); c.commit(); c.close()"
```

Or delete the database file entirely:
```bash
cd Secure-application/Server
rm secure_messaging.db
```

## Correct Run Order

1. **Start the server** (port 8000)
   ```bash
   cd Secure-application/Server
   python -m uvicorn main:app --host 127.0.0.1 --port 8000
   ```

2. **Bob registers first** — Bob must upload his keys before Alice sends.
   - Open keyboard app → Secure Messaging → Register as Bob
   - Or run CLI: `cd Secure-application/demos/server\ CLI\ demos && python bob.py`

3. **Alice registers** — Then Alice searches, creates conversation, and sends.
   - Open keyboard app → Secure Messaging → Register as Alice → Search Bob → Start conversation → Send
   - Or run CLI: `python alice.py` (after Bob is running)

4. **Bob receives and decrypts** — Bob opens Inbox → taps message → sees plaintext.

## Android Keyboard Demo

- **App base URL:** `http://10.0.2.2:8000/` (emulator; host machine's localhost)
- **Physical device:** Change `NetworkModule.BASE_URL` to your machine's LAN IP (e.g. `http://192.168.x.x:8000/`)

## Optional: Force Mock Obfuscation for Demos

If the external steganography API is slow or fails, force mock obfuscation for stable demos:

1. Create or edit `Secure-application/Server/.env`
2. Add: `USE_MOCK_OBFUSCATION=true`
3. Restart the server

Mock obfuscation stores the ciphertext directly in metadata (no external API calls). Decryption still works normally.

## If Decryption Still Fails

- **"Wrong key or tampered data"** — Keys are out of sync. Clear DB and re-register both users in the correct order (Bob first, then Alice).
- **"Cannot connect to server"** — Ensure server runs on port 8000 and the app's base URL matches.
- **"No ephemeral key provided"** — First message must include ephemeral key. This is automatic; if you see this, report a bug.
