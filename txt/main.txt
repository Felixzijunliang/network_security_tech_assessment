import sys
import time


def print_header(title: str):
    print(title.center(80))


def print_menu():
    print_header("Network Security Technology Demonstration System")
    print("""
Select what you want to demonstrate:

1. Huffman Coding demonstration
   - Demonstrate the principles of data compression
   - Encoding and decoding process

2. RSA encryption demonstration
   - Key generation
   - Encryption and decryption processes

3. Secure communication system demonstration
   - Combining Huffman coding and RSA encryption
   - Full end-to-end encrypted communication

4. Man-in-the-middle attack demonstration
   - Scenario 1: Failed attack (correct key exchange)
   - Scenario 2: Successful attack (attacker controls key exchange)
   - Defense methods

5. Timing attack demonstration
   - Timing attack principle
   - Attacks on vulnerable implementations
   - Security implementation comparison
   - Defense methods

6. Full demo (running all modules)

0. Exit

""")


def demo_huffman():
    """Huffman coding demonstration"""
    print_header("Huffman Coding Demonstration")
    
    try:
        from huffman import HuffmanCoding
        
        huffman = HuffmanCoding()
        
        # Get user input
        print("\nPlease enter text to compress (supports Chinese and English):")
        text = input("> ").strip()
        
        if not text:
            text = "hello world! this is a demonstration of huffman coding for data compression."
            print(f"Using default text: {text}")
        
        print(f"\nOriginal text: {text}")
        print(f"Original size: {len(text)} characters ({len(text.encode('utf-8')) * 8} bits)")
        
        # Encode
        encoded, codes = huffman.encode(text)
        print(f"\nEncoded size: {len(encoded)} bits")
        print(f"Compression ratio: {huffman.get_compression_ratio(text, encoded):.2f}%")
        
        # Display partial encoding table
        print("\nPartial Huffman encoding table:")
        print("-" * 40)
        for i, (char, code) in enumerate(sorted(codes.items())[:10]):
            print(f"'{char}': {code}")
        if len(codes) > 10:
            print(f"... and {len(codes) - 10} more characters")
        print("-" * 40)
        
        # Decode
        decoded = huffman.decode(encoded)
        print(f"\nDecoding verification: {'✓ Success' if text == decoded else '✗ Failed'}")
        
    except Exception as e:
        print(f"\nError: {e}")
    
    input("\nPress Enter to continue...")


def demo_rsa():
    """RSA encryption demonstration"""
    print_header("RSA Encryption Demonstration")
    
    try:
        from rsa_crypto import RSA
        
        print("\nInitializing RSA system (512-bit key)...")
        rsa = RSA(key_size=512)
        public_key, private_key = rsa.generate_keys()
        
        print(f"\nPublic key (e, n):")
        print(f"  e = {public_key[0]}")
        print(f"  n bit length = {public_key[1].bit_length()} bits")
        
        # Get user input
        print("\nPlease enter text to encrypt (supports Chinese and English):")
        message = input("> ").strip()
        
        if not message:
            message = "Hello, RSA! 你好，RSA加密！"
            print(f"Using default text: {message}")
        
        print(f"\nOriginal message: {message}")
        
        # Encrypt
        encrypted_blocks = RSA.encrypt_string(message, public_key)
        print(f"Encrypted: {len(encrypted_blocks)} ciphertext blocks")
        
        # Decrypt
        decrypted = RSA.decrypt_string(encrypted_blocks, private_key)
        print(f"Decrypted: {decrypted}")
        
        print(f"\nEncryption-Decryption verification: {'✓ Success' if message == decrypted else '✗ Failed'}")
        
    except Exception as e:
        print(f"\nError: {e}")
    
    input("\nPress Enter to continue...")


def demo_secure_communication():
    """Secure communication system demonstration"""
    print_header("Secure Communication System Demonstration")
    
    try:
        from secure_communication import CommunicationParty
        
        print("\nInitializing communication system...")
        alice = CommunicationParty("Alice", key_size=512)
        bob = CommunicationParty("Bob", key_size=512)
        
        # Exchange public keys
        print("Public Key Exchange")
        alice_public = alice.get_public_key()
        bob_public = bob.get_public_key()
        print("[Alice] Public key shared")
        print("[Bob] Public key shared")
        
        # Get user input
        print("\nPlease enter message for Alice to send to Bob (supports Chinese and English):")
        message = input("> ").strip()
        
        if not message:
            message = "Hello Bob! This is a secret message that will be compressed and encrypted. 你好Bob！这是一条秘密消息。"
            print(f"Using default message: {message}")
        
        transmission = alice.send_to(message, bob_public)
        
        # Receive message
        received = bob.receive_from(transmission)
        
        # Verify
        print("Verification")
        print(f"Message integrity: {'✓ Success' if message == received else '✗ Failed'}")
        
    except Exception as e:
        print(f"\nError: {e}")
    
    input("\nPress Enter to continue...")


def demo_mitm_attack():
    """Man-in-the-middle attack demonstration"""
    print_header("Man-in-the-Middle Attack Demonstration")
    
    try:
        from mitm_attack import demo_failed_mitm_attack, demo_successful_mitm_attack, demo_prevention
        
        print("\nWill demonstrate two scenarios:")
        print("1. Failed man-in-the-middle attack")
        print("2. Successful man-in-the-middle attack")
        
        input("\nPress Enter to start demonstration...")
        
        # Scenario 1
        demo_failed_mitm_attack()
        
        input("\nPress Enter to continue to next scenario...")
        
        # Scenario 2
        demo_successful_mitm_attack()
        
        # Prevention methods
        demo_prevention()
        
    except Exception as e:
        print(f"\nError: {e}")
    
    input("\nPress Enter to continue...")


def demo_timing_attack():
    """Timing attack demonstration"""
    print_header("Timing Attack Demonstration")
    
    try:
        from timing_attack import (demo_timing_attack_basics,
                                   demo_timing_attack_vulnerable,
                                   demo_timing_attack_comparison,
                                   demo_timing_attack_prevention)
        
        print("\nWill demonstrate:")
        print("1. Basic timing attack principles")
        print("2. Attack on vulnerable implementation")
        print("3. Comparison of secure vs vulnerable implementation")
        print("4. Defense methods")
        
        input("\nPress Enter to start demonstration...")
        
        # Demo 1: Principles
        demo_timing_attack_basics()
        
        input("\nPress Enter to continue...")
        
        # Demo 2: Attack
        demo_timing_attack_vulnerable()
        
        input("\nPress Enter to continue...")
        
        # Demo 3: Comparison
        demo_timing_attack_comparison()
        
        # Demo 4: Defense
        demo_timing_attack_prevention()
        
    except Exception as e:
        print(f"\nError: {e}")
    
    input("\nPress Enter to continue...")


def demo_all():
    """Run all demonstrations"""
    print_header("Complete Demonstration")
    print("\nWill run all demonstration modules in sequence...")
    
    demos = [
        ("Huffman Coding", demo_huffman),
        ("RSA Encryption", demo_rsa),
        ("Secure Communication System", demo_secure_communication),
        ("Man-in-the-Middle Attack", demo_mitm_attack),
        ("Timing Attack", demo_timing_attack)
    ]
    
    for i, (name, func) in enumerate(demos, 1):
        print(f"Part {i}/{len(demos)}: {name}")
        
        try:
            func()
        except KeyboardInterrupt:
            print("\n\nDemonstration interrupted")
            return
        except Exception as e:
            print(f"\nError: {e}")
            input("\nPress Enter to continue...")
    
    print_header("All Demonstrations Completed")


def main():
    while True:
        try:
            print_menu()
            choice = input("Please enter your choice (0-6): ").strip()
            
            if choice == "0":
                print("\nThank you for using! Goodbye!")
                break
            elif choice == "1":
                demo_huffman()
            elif choice == "2":
                demo_rsa()
            elif choice == "3":
                demo_secure_communication()
            elif choice == "4":
                demo_mitm_attack()
            elif choice == "5":
                demo_timing_attack()
            elif choice == "6":
                demo_all()
            else:
                print("\nInvalid choice, please try again.")
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\n\nProgram interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\nError occurred: {e}")
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()

