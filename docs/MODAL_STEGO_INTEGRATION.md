# Modal Stego Integration

This document describes how Secure Keyboard integrates external steganography endpoints:

- Encode endpoint: `https://modalcd--encode.modal.run/`
- Decode endpoint: `https://modalcd--decode.modal.run/`

## What changed

The app no longer uses backend `/api/obfuscation/obfuscate` and `/api/obfuscation/deobfuscate` for message wrapping.

Current message pipeline:

1. Build encrypted payload locally (`counter + ciphertext`) in `SecureMessagingRepository`.
2. Convert packed bytes to a bitstring (`0`/`1`).
3. Call Modal encode endpoint to embed bits into natural text.
4. Send the returned text to the user.
5. On receive, call Modal decode endpoint to recover bits.
6. Convert bits back to bytes, unpack counter/ciphertext, then decrypt locally.

## App wiring

### API models/services

File: `app/src/main/java/com/frogobox/appkeyboard/data/remote/StegoApiService.kt`

- `StegoEncodeApiService.encode(StegoEncodeRequest)`
- `StegoDecodeApiService.decode(StegoDecodeRequest)`

DTOs:

- `StegoEncodeRequest(context, bits)`
- `StegoEncodeResponse(text, ac_token_count?, prompt?)`
- `StegoDecodeRequest(text)`
- `StegoDecodeResponse(bits)`

### DI setup

File: `app/src/main/java/com/frogobox/appkeyboard/di/NetworkModule.kt`

- Adds separate Retrofit clients for encode/decode hosts.
- Uses `@Named("stegoClient")` with no auth interceptor.
- Keeps bearer token injection only for secure backend host.

### Repository flow

File: `app/src/main/java/com/frogobox/appkeyboard/data/repository/SecureMessagingRepository.kt`

- `sendMessage(...)`:
  - fetch counter
  - encrypt + pack
  - `ByteArray.toBitString()`
  - call `stegoEncodeApi.encode(...)`
- `decryptMessage(...)`:
  - call `stegoDecodeApi.decode(...)`
  - `bitStringToByteArray(...)`
  - unpack + decrypt + parse payload

## Endpoint contracts

### Encode request

```json
{
  "context": "car",
  "bits": "010101..."
}
```

### Encode response

```json
{
  "text": "Natural looking generated sentence",
  "ac_token_count": 34,
  "prompt": "..."
}
```

### Decode request

```json
{
  "text": "Natural looking generated sentence"
}
```

### Decode response

```json
{
  "bits": "010101..."
}
```

## Local API smoke test

Use PowerShell from any machine with internet access:

```powershell
# Encode
$encBody = @{ context = 'car'; bits = '0101010101010101' } | ConvertTo-Json
Invoke-RestMethod -Uri 'https://modalcd--encode.modal.run/' -Method Post -ContentType 'application/json' -Body $encBody

# Decode (replace with returned text)
$decBody = @{ text = 'REPLACE_WITH_ENCODED_TEXT' } | ConvertTo-Json
Invoke-RestMethod -Uri 'https://modalcd--decode.modal.run/' -Method Post -ContentType 'application/json' -Body $decBody
```

## Notes and limits

- Decode output must be only bits (`0`/`1`) and length must be a multiple of 8.
- `bitStringToByteArray` strips whitespace and validates format.
- App currently sends fixed one-word context: `car`.
- Keep endpoint URLs configurable for future environment switching.
