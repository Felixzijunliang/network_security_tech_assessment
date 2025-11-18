from secure_communication import CommunicationParty, SecureCommunication
from rsa_crypto import RSA
from typing import Dict, Tuple
import json
import random


class ManInTheMiddle:
    def __init__(self, name: str = "Mallory"):
        self.name = name
        self.comm = SecureCommunication(rsa_key_size=512)
        print(f"[{self.name}] Attacker initialization")
        self.comm.setup_keys()
        
        # Save intercepted keys
        self.alice_public_key = None
        self.bob_public_key = None
        self.intercepted_messages = []
    
    def get_public_key(self) -> Tuple[int, int]:
        """Get attacker's public key"""
        return self.comm.get_public_key()
    
    def intercept_key_exchange(self, alice_public: Tuple[int, int], bob_public: Tuple[int, int]):
        print(f"[{self.name}] Intercepting key exchange")
        
        self.alice_public_key = alice_public
        self.bob_public_key = bob_public
        
        print(f"[{self.name}] ✓ Intercepted Alice's public key")
        print(f"[{self.name}] ✓ Intercepted Bob's public key")
        print(f"[{self.name}] ⚠ Can now impersonate both parties")
    
    def intercept_and_forward(self, transmission: Dict, from_party: str, to_party: str) -> Dict:
        print(f"[{self.name}] Intercepting message: {from_party} -> {to_party}")
        
        print(f"[{self.name}] Intercepted encrypted message")
        print(f"[{self.name}] Number of encrypted blocks: {len(transmission['encrypted_blocks'])}")
        
        # Save intercepted message
        self.intercepted_messages.append({
            'from': from_party,
            'to': to_party,
            'transmission': transmission
        })
        
        print(f"[{self.name}] ⚠ Cannot decrypt message (no private key)")
        print(f"[{self.name}] → Forwarding to {to_party}")
        
        return transmission
    
    def intercept_decrypt_modify_encrypt(self, transmission: Dict, from_party: str, to_party: str,
                                        sender_public: Tuple[int, int],
                                        receiver_public: Tuple[int, int]) -> Dict:
        print(f"[{self.name}] Executing man-in-the-middle attack")
        
        print(f"[{self.name}] 1. Intercepting message from {from_party} to {to_party}")
        
        print(f"[{self.name}] 2. Decrypting message with attacker's private key...")
        encrypted_blocks = transmission['encrypted_blocks']
        decrypted_str = RSA.decrypt_string(encrypted_blocks, self.comm.private_key)
        
        # Unpack
        package = json.loads(decrypted_str)
        encoded_bits = package['encoded_bits']
        huffman_codes = package['huffman_codes']
        
        # Huffman decode to get original message
        original_message = self.comm.huffman.decode(encoded_bits, huffman_codes)
        print(f"[{self.name}] ✓ Successfully decrypted original message: {original_message}")
        
        modified_message = self._modify_message(original_message)
        print(f"[{self.name}] 3. Modified message: {modified_message}")
        
        # Re-encode and encrypt, send to real receiver
        print(f"[{self.name}] 4. Re-encrypting and sending to {to_party}...")
        
        # Huffman encode
        new_encoded_bits, new_huffman_codes = self.comm.huffman.encode(modified_message)
        
        # Package
        new_package = {
            'encoded_bits': new_encoded_bits,
            'huffman_codes': new_huffman_codes
        }
        new_package_str = json.dumps(new_package)
        
        # Encrypt with receiver's real public key
        new_encrypted_blocks = RSA.encrypt_string(new_package_str, receiver_public)
        
        # Create new transmission package
        new_transmission = {
            'encrypted_blocks': new_encrypted_blocks,
            'sender': from_party,  # Impersonate original sender
            'receiver': to_party
        }
        
        print(f"[{self.name}] ✓ Attack successful! Message has been tampered and forwarded")
        
        # Save attack record
        self.intercepted_messages.append({
            'from': from_party,
            'to': to_party,
            'original': original_message,
            'modified': modified_message
        })
        
        return new_transmission
    
    def _modify_message(self, original: str) -> str:
        modifications = [
            lambda msg: msg.replace("secret", "public"),
            lambda msg: msg.replace("confidential", "open"),
            lambda msg: msg.replace("$1000", "$1"),
            lambda msg: msg.replace("approved", "rejected"),
            lambda msg: msg + " [MODIFIED BY ATTACKER]",
            lambda msg: "FAKE MESSAGE: " + msg
        ]
        
        # Randomly select a modification method
        modification = random.choice(modifications)
        return modification(original)
    
    def show_intercepted_messages(self):
        """Display all intercepted messages"""
        print(f"\n{'='*60}")
        print(f"[{self.name}] Intercepted message log")
        print(f"{'='*60}")
        
        for i, msg in enumerate(self.intercepted_messages, 1):
            print(f"\nMessage #{i}:")
            print(f"  From: {msg['from']}")
            print(f"  To: {msg['to']}")
            if 'original' in msg:
                print(f"  Original message: {msg['original']}")
                print(f"  Modified to: {msg['modified']}")
            else:
                print(f"  Status: Cannot decrypt")


def demo_failed_mitm_attack():
    print("Scenario 1: Failed Man-in-the-Middle Attack (Correct Key Exchange)")
    print("Description: Alice and Bob correctly exchanged their public keys")
    print("Attacker can only intercept encrypted data but cannot decrypt")
    
    # Create communication parties
    alice = CommunicationParty("Alice", key_size=512)
    bob = CommunicationParty("Bob", key_size=512)
    mallory = ManInTheMiddle("Mallory")
    
    # Correct key exchange
    print("\n[System] Alice and Bob are exchanging public keys...")
    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()
    
    # Attacker attempts to intercept (but can only see encrypted data)
    mallory.intercept_key_exchange(alice_public, bob_public)
    
    # Alice sends message to Bob
    print("\nPlease enter message for Alice to send to Bob (supports Chinese and English):")
    print("(Press Enter for default message)")
    message = input("> ").strip()
    
    if not message:
        message = "Hello Bob! This is a secret message. The password is: SECRET123"
        print(f"Using default message: {message}")
    
    print(f"\n[Alice] Original message: {message}")
    
    transmission = alice.send_to(message, bob_public)
    
    # Attacker intercepts message (but cannot decrypt)
    transmission = mallory.intercept_and_forward(transmission, "Alice", "Bob")
    
    # Bob receives message
    received = bob.receive_from(transmission)
    
    # Results
    print("Results")
    print(f"[Bob] Received message: {received}")
    print(f"Message integrity: {'✓ Success' if message == received else '✗ Failed'}")
    print(f"[Conclusion] Attacker cannot decrypt message, communication is secure ✓")


def demo_successful_mitm_attack():
    print("Scenario 2: Successful Man-in-the-Middle Attack (Attacker Controls Key Exchange)")
    print("Description: Attacker intervenes during key exchange phase")
    print("Alice thinks she's communicating with Bob (actually with attacker)")
    print("Bob thinks he's communicating with Alice (actually with attacker)")
    
    # Create communication parties
    alice = CommunicationParty("Alice", key_size=512)
    bob = CommunicationParty("Bob", key_size=512)
    mallory = ManInTheMiddle("Mallory")
    
    # Get real public keys
    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()
    mallory_public = mallory.get_public_key()
    
    # Attacker intercepts key exchange
    mallory.intercept_key_exchange(alice_public, bob_public)
    
    print("\n[System] Key exchange controlled by attacker:")
    print("  - Alice received 'Bob's public key' which is actually attacker's public key")
    print("  - Bob received 'Alice's public key' which is actually attacker's public key")
    
    # Alice sends message (thinks to Bob, actually to attacker)
    print("\nPlease enter message for Alice to send (supports Chinese and English):")
    print("(Press Enter for default message)")
    message = input("> ").strip()
    
    if not message:
        message = "Hello Bob! The transfer amount is $1000. Please approve this confidential transaction."
        print(f"Using default message: {message}")
    
    print(f"\n[Alice] Original message: {message}")
    
    # Alice encrypts with attacker's public key (thinks it's Bob's)
    transmission = alice.send_to(message, mallory_public)
    
    # Attacker intercepts, decrypts, modifies, re-encrypts
    modified_transmission = mallory.intercept_decrypt_modify_encrypt(
        transmission, "Alice", "Bob",
        alice_public, bob_public
    )
    
    # Bob receives message
    received = bob.receive_from(modified_transmission)
    
    # Results
    print("Results")
    print(f"[Alice] Sent message: {message}")
    print(f"[Bob] Received message: {received}")
    print(f"Message was tampered: {'✗ Yes' if message != received else '✓ No'}")
    print(f"[Conclusion] Attacker successfully tampered with the message! Communication is insecure ✗")
    
    # Show attack log
    mallory.show_intercepted_messages()


def demo_prevention():
    """Demonstrate how to defend against man-in-the-middle attacks"""
    print("Methods to Defend Against Man-in-the-Middle Attacks")
    



if __name__ == "__main__":

    print("Man-in-the-Middle Attack Demonstration")

    
    # Scenario 1: Failed attack
    demo_failed_mitm_attack()
    
    # Scenario 2: Successful attack
    demo_successful_mitm_attack()
    
    # Prevention methods
    demo_prevention()
