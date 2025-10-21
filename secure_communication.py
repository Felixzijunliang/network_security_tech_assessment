from huffman import HuffmanCoding
from rsa_crypto import RSA
from typing import Tuple, Dict
import json


class SecureCommunication:
    
    def __init__(self, rsa_key_size: int = 512):
        self.huffman = HuffmanCoding()
        self.rsa = RSA(key_size=rsa_key_size)
        self.public_key = None
        self.private_key = None
    
    def setup_keys(self):
        print("\n[Secure Communication] Initializing encryption system...")
        self.public_key, self.private_key = self.rsa.generate_keys()
        print("[Secure Communication] Key generation complete")
    
    def get_public_key(self) -> Tuple[int, int]:
        return self.public_key
    
    def send_message(self, message: str, receiver_public_key: Tuple[int, int]) -> Dict:
        print("\n[Sender] Preparing to send message...")
        print(f"[Sender] Original message: {message}")
        print(f"[Sender] Original length: {len(message)} characters")
        
        # Step 1: Huffman coding compression
        print("\n[Sender] Step 1: Compressing with Huffman coding...")
        encoded_bits, huffman_codes = self.huffman.encode(message)
        print(f"[Sender] Compressed to: {len(encoded_bits)} bits")
        compression_ratio = self.huffman.get_compression_ratio(message, encoded_bits)
        print(f"[Sender] Compression ratio: {compression_ratio:.2f}%")
        
        # Convert binary string to integer for encryption
        # For large messages, we need to split into blocks
        print("\n[Sender] Step 2: Encrypting with RSA...")
        
        # Package encoded bits and Huffman codes
        package = {
            'encoded_bits': encoded_bits,
            'huffman_codes': huffman_codes
        }
        package_str = json.dumps(package)
        
        # RSA encryption
        encrypted_blocks = RSA.encrypt_string(package_str, receiver_public_key)
        print(f"[Sender] Encryption complete, generated {len(encrypted_blocks)} encrypted blocks")
        
        # Create transmission package
        transmission = {
            'encrypted_blocks': encrypted_blocks,
            'sender': 'Alice',
            'receiver': 'Bob'
        }
        
        print("[Sender] Message sent successfully")
        return transmission
    
    def receive_message(self, transmission: Dict) -> str:
        print("\n[Receiver] Received encrypted message...")
        
        # Step 1: RSA decryption
        print("[Receiver] Step 1: Decrypting with RSA...")
        encrypted_blocks = transmission['encrypted_blocks']
        print(f"[Receiver] Received {len(encrypted_blocks)} encrypted blocks")
        
        decrypted_str = RSA.decrypt_string(encrypted_blocks, self.private_key)
        
        # Unpack
        package = json.loads(decrypted_str)
        encoded_bits = package['encoded_bits']
        huffman_codes = package['huffman_codes']
        
        print(f"[Receiver] Decryption complete, got {len(encoded_bits)} bits of compressed data")
        
        # Step 2: Huffman decoding
        print("[Receiver] Step 2: Decompressing with Huffman coding...")
        decoded_message = self.huffman.decode(encoded_bits, huffman_codes)
        print(f"[Receiver] Decompression complete, recovered message: {decoded_message}")
        
        return decoded_message


class CommunicationParty:
    """Communication party"""
    
    def __init__(self, name: str, key_size: int = 512):
        self.name = name
        self.comm = SecureCommunication(rsa_key_size=key_size)
        print(f"[{self.name}] Initializing communication system")
        self.comm.setup_keys()
    
    def get_public_key(self) -> Tuple[int, int]:
        """Get public key"""
        return self.comm.get_public_key()
    
    def send_to(self, message: str, receiver_public_key: Tuple[int, int]) -> Dict:
        """Send message to other party"""
        print(f"[{self.name}] Sending message")
        return self.comm.send_message(message, receiver_public_key)
    
    def receive_from(self, transmission: Dict) -> str:
        """Receive message"""
        print(f"[{self.name}] Receiving message")
        return self.comm.receive_message(transmission)


if __name__ == "__main__":
    print("Secure Communication System Demonstration")
    
    # Create two communication parties: Alice and Bob
    alice = CommunicationParty("Alice", key_size=512)
    bob = CommunicationParty("Bob", key_size=512)
    
    # Exchange public keys

    print("Public Key Exchange")
    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()
    print(f"[Alice] Public key shared")
    print(f"[Bob] Public key shared")
    
    # Alice sends message to Bob
    print("\nPlease enter message for Alice to send to Bob (supports Chinese and English):")
    print("(Press Enter for default message)")
    message = input("> ").strip()
    
    if not message:
        message = "Hello Bob! This is a secret message from Alice. Let's test the secure communication system with Huffman coding and RSA encryption! 你好Bob！这是来自Alice的秘密消息。"
        print(f"Using default message: {message}")
    
    transmission = alice.send_to(message, bob_public)
    
    # Bob receives message
    received_message = bob.receive_from(transmission)
    
    # Verify
    print("Verification Results")
    print(f"Original message: {message}")
    print(f"Received message: {received_message}")
    print(f"Message integrity: {'✓ Success' if message == received_message else '✗ Failed'}")
