Here is the breakdown of how the secure messaging system is going to work. The main goal is to make the traffic look completely normal while keeping the actual data secure and lightweight.

1. Remote Key Exchange (The Handshake)
To avoid meeting in person, we use an algorithm that allows two people to create a shared secret over a public connection.
•	Algorithm: X3DH (Extended Triple Diffie-Hellman).
•	How it works: Each user publishes a set of "Pre-keys" to a public bundle. When User A wants to talk to User B, they pull B’s bundle and perform a series of Diffie-Hellman calculations.
•	Result: Both users end up with the same Master_Shared_Secret without ever actually sending the key itself.
2. The Generator (PRNG)
•	Logic: Both keyboards feed the Master Secret into an HKDF-SHA256 function.
•	Result: They both generate the exact same infinite stream of random numbers (Nonces/IVs) in the same order.
3. Enhanced Encryption
We don’t want to use the Master Secret for every message.
•	Algorithm: XChaCha20-Poly1305.
•	The Process: For every new message, we take the Next_Random_Number from our PRNG1 and use that as the encryption key for that specific message.
•	Why: This provides "Perfect Forward Secrecy." Even if one message key is somehow leaked, the Master Secret remains safe.
4. Obfuscation (The Nishant Server "Black Box")
Instead of the keyboard generating the camouflage text, the server handles it for speed.
•	The Setup: The Nishant Server runs its own PRNG2 to generate thousands of "Fresh Random Bytes." It maps these bytes to natural language sentences (e.g., 0xAF32 = "How's the weather?").
•	The List: The server maintains a massive lookup table of these pre-generated obfuscated messages, indexed by a Message_ID.
________________________________________
6. Sending the Message
The user types "Meeting at 9pm" into the custom keyboard.
•	Step A (Encrypt): The keyboard encrypts the text using the Next_Random_Number from its local PRNG1.
•	Step B (Blind Upload): The keyboard sends this Encrypted Ciphertext to the Nishant Server.
•	Step C (Server Role): The server cannot read this ciphertext (it has no keys). It simply stores the ciphertext and assigns it to the next available Obfuscated_Text from its pre-generated list.
•	Step D (WhatsApp): The server sends back the decoy text: "I'm going to the grocery store." The keyboard pastes this into WhatsApp. User hits send.
7. Receiving the Message
The receiver sees "I'm going to the grocery store" on WhatsApp.
•	Step A (Intercept): The receiver's keyboard identifies the decoy text.
•	Step B (Request): The keyboard asks the Nishant Server: "Give me the encrypted data associated with this decoy text."
•	Step C (Download): The server sends the Encrypted Ciphertext to the receiver.
•	Step D (Local Decrypt): The receiver's keyboard pulls the Next_Random_Number from its own local PRNG1 (which matches the sender's) and decrypts the ciphertext.
•	Step E (Display): The keyboard displays the hidden message: "Meeting at 9pm".
5. Re-synchronization (The Safety Net)
•	The Logic: If a message is skipped, the receiver's keyboard "cranks" its PRNG1 forward (Linear Search) to try the next 10-20 random numbers until the decryption is successful.

