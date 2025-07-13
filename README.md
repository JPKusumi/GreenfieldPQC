# Can your toolkit support this scenario?

Alice and Bob are old friends who love sharing secrets, but in this digital age, they're paranoid about eavesdroppers—like quantum computers that could one day crack traditional key exchanges. Alice wants to send Bob some confidential photos from their latest adventure, but she needs a super-secure way to encrypt them using her new favorite symmetric cipher, Kusumi512, which requires a 512-bit shared key. The problem? They don't have a secure way to agree on that key over the internet without someone intercepting it.

Enter Kyber, the post-quantum hero of key encapsulation mechanisms (KEMs). It's like a magical lockbox that's safe even from future quantum villains. Here's how their story unfolds:

1. **Alice Prepares the Lockbox**: Alice generates a Kyber key pair on her computer—a public key (like an open lock anyone can see) and a private key (the secret code to unlock it). She sends the public key to Bob over the open internet. No worries if someone like Eve intercepts it; the public key is useless without the private one.

2. **Bob Seals the Secret**: Bob receives Alice's public key and decides on a random shared secret (this will become their 512-bit Kusumi512 key). Using Kyber, he "encapsulates" this secret inside a ciphertext—a digital envelope sealed with Alice's public key. Only Alice can open it. Bob sends this ciphertext back to Alice.

3. **Alice Unlocks the Secret**: Alice uses her private key to "decapsulate" the ciphertext, revealing the exact shared secret Bob chose. Now both Alice and Bob have the same 512-bit key, and Eve (even with a quantum computer) can't figure it out because Kyber's lattice-based math is too tricky for Shor's algorithm.

4. **Symmetric Bliss with Kusumi512**: With the shared key in hand, Alice encrypts her photos using Kusumi512 in a mode like CTR (counter mode) for fast streaming. For extra security, she adds authentication with Poly1305, creating an AEAD (Authenticated Encryption with Associated Data) tag to ensure the data isn't tampered with. She sends the encrypted photos and tag to Bob.

5. **Bob Decrypts and Enjoys**: Bob uses the same shared Kusumi512 key to decrypt the photos and verify the Poly1305 tag. If everything checks out, he sees the images perfectly. If not, he knows something's fishy.

In the end, Alice and Bob's communication is quantum-safe from the start (thanks to Kyber) and blazing fast for the bulk data (thanks to Kusumi512's efficiency). This hybrid approach—post-quantum key exchange plus symmetric encryption—is the gold standard for future-proofing, enabled by your GreenfieldPQC toolkit. If quantum threats escalate, they're ready!
