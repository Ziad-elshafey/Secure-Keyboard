import requests
import json
import base64
import os

BASE = 'http://127.0.0.1:8000'

print('=== STEP 1: Register users ===')
r1 = requests.post(f'{BASE}/api/auth/register', json={'username': 'alice', 'email': 'alice@test.com', 'password': 'password123'})
print(f'Register alice: {r1.status_code} {r1.text[:200]}')

r2 = requests.post(f'{BASE}/api/auth/register', json={'username': 'bob', 'email': 'bob@test.com', 'password': 'password123'})
print(f'Register bob: {r2.status_code} {r2.text[:200]}')

print('\n=== STEP 2: Login ===')
l1 = requests.post(f'{BASE}/api/auth/login', json={'username': 'alice', 'password': 'password123'})
print(f'Login alice: {l1.status_code}')
alice_data = l1.json() if l1.status_code == 200 else {}
alice_token = alice_data.get('access_token', '')
alice_id = alice_data.get('user_id', '')
print(f'  alice_id={alice_id}')

l2 = requests.post(f'{BASE}/api/auth/login', json={'username': 'bob', 'password': 'password123'})
print(f'Login bob: {l2.status_code}')
bob_data = l2.json() if l2.status_code == 200 else {}
bob_token = bob_data.get('access_token', '')
bob_id = bob_data.get('user_id', '')
print(f'  bob_id={bob_id}')

print('\n=== STEP 3: Upload key bundles ===')
fake_key = base64.b64encode(os.urandom(32)).decode()
fake_sig = base64.b64encode(os.urandom(64)).decode()

for name, token in [('alice', alice_token), ('bob', bob_token)]:
    kr = requests.post(f'{BASE}/api/keys/bundle', json={
        'identity_key_public': fake_key,
        'signed_prekey_public': fake_key,
        'signed_prekey_signature': fake_sig,
        'signed_prekey_id': 1
    }, headers={'Authorization': f'Bearer {token}'})
    print(f'Upload keys {name}: {kr.status_code} {kr.text[:200]}')

print('\n=== STEP 4: Search bob ===')
sr = requests.get(f'{BASE}/api/users/search/?query=bob', headers={'Authorization': f'Bearer {alice_token}'})
print(f'Search: {sr.status_code} {sr.text[:300]}')

print('\n=== STEP 5: Create session ===')
cs = requests.post(f'{BASE}/api/sessions/', json={'peer_username': 'bob'}, headers={'Authorization': f'Bearer {alice_token}'})
print(f'Create session: {cs.status_code} {cs.text[:300]}')
session_id = cs.json().get('session_id', '') if cs.status_code in [200, 201] else ''
print(f'  session_id={session_id}')

print('\n=== STEP 6: Get counter ===')
if session_id:
    cr = requests.post(f'{BASE}/api/sessions/{session_id}/counter', headers={'Authorization': f'Bearer {alice_token}'})
    print(f'Counter: {cr.status_code} {cr.text[:200]}')

print('\n=== STEP 7: Obfuscate ===')
fake_ciphertext = os.urandom(14) + b'\x00\x01'
ct_b64 = base64.b64encode(fake_ciphertext).decode()
print(f'  Sending {len(fake_ciphertext)} bytes as b64: {ct_b64}')
ob = requests.post(f'{BASE}/api/obfuscation/obfuscate', json={'ciphertext_b64': ct_b64}, headers={'Authorization': f'Bearer {alice_token}'}, timeout=120)
print(f'Obfuscate: {ob.status_code}')
if ob.status_code == 200:
    ob_data = ob.json()
    print(f'  obfuscated_text: {ob_data.get("obfuscated_text", "")[:100]}...')
    print(f'  seed_id: {ob_data.get("seed_id", "")}')
    seed_id = ob_data.get('seed_id', '')
    obfuscated_text = ob_data.get('obfuscated_text', '')

    print('\n=== STEP 8: Deobfuscate ===')
    de = requests.post(f'{BASE}/api/obfuscation/deobfuscate', json={
        'obfuscated_text': obfuscated_text,
        'seed_id': seed_id
    }, headers={'Authorization': f'Bearer {alice_token}'}, timeout=120)
    print(f'Deobfuscate: {de.status_code}')
    if de.status_code == 200:
        de_data = de.json()
        recovered_b64 = de_data.get('ciphertext_b64', '')
        recovered = base64.b64decode(recovered_b64)
        print(f'  Recovered {len(recovered)} bytes')
        print(f'  Match: {recovered == fake_ciphertext}')
    else:
        print(f'  ERROR: {de.text[:500]}')
else:
    print(f'  ERROR: {ob.text[:500]}')

print('\n=== DONE ===')
