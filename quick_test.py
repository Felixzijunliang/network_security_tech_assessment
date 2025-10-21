import sys


def test_huffman():
    print("Testing Huffman coding...")
    
    try:
        from huffman import HuffmanCoding
        
        huffman = HuffmanCoding()
        text = "hello world"
        
        # Encode
        encoded, codes = huffman.encode(text)
        # Decode
        decoded = huffman.decode(encoded)
        
        assert text == decoded, "Decoding failed"
        print("✓ Huffman coding test passed")
        return True
    except Exception as e:
        print(f"✗ Huffman coding test failed: {e}")
        return False


def test_rsa():
    print("Testing RSA encryption...")
    
    try:
        from rsa_crypto import RSA
        
        # Use smaller key to speed up testing
        rsa = RSA(key_size=256)
        public_key, private_key = rsa.generate_keys()
        
        # Test integer encryption
        message = 42
        encrypted = RSA.encrypt(message, public_key)
        decrypted = RSA.decrypt(encrypted, private_key)
        
        assert message == decrypted, "Integer encryption-decryption failed"
        
        # Test string encryption
        text = "Test"
        encrypted_blocks = RSA.encrypt_string(text, public_key)
        decrypted_text = RSA.decrypt_string(encrypted_blocks, private_key)
        
        assert text == decrypted_text, "String encryption-decryption failed"
        
        print("✓ RSA encryption test passed")
        return True
    except Exception as e:
        print(f"✗ RSA encryption test failed: {e}")
        return False


def test_secure_communication():
    print("Testing secure communication system...")

    
    try:
        from secure_communication import CommunicationParty
        
        # Create communication parties
        alice = CommunicationParty("Alice", key_size=256)
        bob = CommunicationParty("Bob", key_size=256)
        
        # Exchange public keys
        alice_public = alice.get_public_key()
        bob_public = bob.get_public_key()
        
        # Send message
        message = "Test message"
        transmission = alice.send_to(message, bob_public)
        received = bob.receive_from(transmission)
        
        assert message == received, "Message transmission failed"
        
        print("✓ Secure communication system test passed")
        return True
    except Exception as e:
        print(f"✗ Secure communication system test failed: {e}")
        return False


def test_imports():
    print("Testing module imports...")
    
    modules = [
        'huffman',
        'rsa_crypto',
        'secure_communication',
        'mitm_attack',
        'timing_attack'
    ]
    
    success = True
    for module in modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except Exception as e:
            print(f"✗ {module}: {e}")
            success = False
    
    return success


def main():
    print("Network Security Technology Project - Quick Test")
    
    tests = [
        ("Module import", test_imports),
        ("Huffman coding", test_huffman),
        ("RSA encryption", test_rsa),
        ("Secure communication", test_secure_communication)
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\nError occurred in test '{name}': {e}")
            results.append((name, False))
    
    # Summary
    print("Test Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ Passed" if result else "✗ Failed"
        print(f"{name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print(" All tests passed! Project is ready.")
        return 0
    else:
        print(f"{total - passed} test(s) failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
