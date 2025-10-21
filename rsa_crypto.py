import random
import time
from typing import Tuple


class RSA:
    
    def __init__(self, key_size: int = 1024):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    @staticmethod
    def _is_prime(n: int, k: int = 5) -> bool:
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Express n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Perform k rounds of testing
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    @staticmethod
    def _generate_prime(bits: int) -> int:
        while True:
            # Generate odd number
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            
            if RSA._is_prime(num):
                return num
    
    @staticmethod
    def _gcd(a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSA._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    @staticmethod
    def _mod_inverse(e: int, phi: int) -> int:
        gcd, x, _ = RSA._extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi
    
    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        print(f"Generating {self.key_size}-bit RSA key...")
        
        # Generate two large primes
        p = self._generate_prime(self.key_size // 2)
        q = self._generate_prime(self.key_size // 2)
        
        # Ensure p and q are different
        while p == q:
            q = self._generate_prime(self.key_size // 2)
        
        # Calculate n and φ(n)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Choose public exponent e
        e = 65537  # Common public exponent
        while self._gcd(e, phi) != 1:
            e = random.randrange(2, phi)
        
        # Calculate private exponent d
        d = self._mod_inverse(e, phi)
        
        # Save keys
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        print("Key generation complete!")
        return self.public_key, self.private_key
    
    @staticmethod
    def encrypt(message: int, public_key: Tuple[int, int]) -> int:
        e, n = public_key
        return pow(message, e, n)
    
    @staticmethod
    def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
        d, n = private_key
        return pow(ciphertext, d, n)
    
    @staticmethod
    def decrypt_vulnerable(ciphertext: int, private_key: Tuple[int, int]) -> int:
        d, n = private_key
        result = 1
        base = ciphertext % n
        exponent = d
        
        # Simple bit-by-bit calculation, vulnerable to timing attacks
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % n
            base = (base * base) % n
            exponent //= 2
        
        return result
    
    @staticmethod
    def decrypt_secure(ciphertext: int, private_key: Tuple[int, int]) -> int:
        d, n = private_key
        
        # Use Python's built-in pow function, more secure
        result = pow(ciphertext, d, n)
        
        # Add random delay to make timing harder to predict
        time.sleep(random.uniform(0.0001, 0.0005))
        
        return result
    
    @staticmethod
    def string_to_int(text: str) -> int:
        return int.from_bytes(text.encode('utf-8'), byteorder='big')
    
    @staticmethod
    def int_to_string(num: int) -> str:
        # Calculate required bytes
        byte_length = (num.bit_length() + 7) // 8
        return num.to_bytes(byte_length, byteorder='big').decode('utf-8', errors='ignore')
    
    @staticmethod
    def encrypt_string(text: str, public_key: Tuple[int, int]) -> list:
        e, n = public_key
        max_block_size = (n.bit_length() - 1) // 8  # Max bytes per block
        
        # Split into blocks
        blocks = []
        text_bytes = text.encode('utf-8')
        
        for i in range(0, len(text_bytes), max_block_size):
            block = text_bytes[i:i + max_block_size]
            block_int = int.from_bytes(block, byteorder='big')
            encrypted_block = RSA.encrypt(block_int, public_key)
            blocks.append(encrypted_block)
        
        return blocks
    
    @staticmethod
    def decrypt_string(encrypted_blocks: list, private_key: Tuple[int, int]) -> str:
        decrypted_bytes = b''
        
        for block in encrypted_blocks:
            decrypted_int = RSA.decrypt(block, private_key)
            # Calculate bytes
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_block = decrypted_int.to_bytes(byte_length, byteorder='big')
            decrypted_bytes += decrypted_block
        
        return decrypted_bytes.decode('utf-8', errors='ignore')


if __name__ == "__main__":
    print("RSA Encryption Test")
    
    # Use smaller key to speed up testing
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keys()
    
    print(f"\nPublic key (e, n): ")
    print(f"  e = {public_key[0]}")
    print(f"  n = {public_key[1]}")
    
    # Test simple integer encryption
    print("Test 1: Integer encryption")
    message = 42
    print(f"Original message: {message}")
    
    encrypted = RSA.encrypt(message, public_key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = RSA.decrypt(encrypted, private_key)
    print(f"Decrypted: {decrypted}")
    print(f"Encryption-decryption success: {message == decrypted}")
    
    # Test string encryption
    print("Test 2: String encryption")
    
    print("\nPlease enter text to encrypt (supports Chinese and English):")
    print("(Press Enter for default text)")
    text = input("> ").strip()
    
    if not text:
        text = "Hello, RSA encryption! 你好，RSA加密！"
        print(f"Using default text: {text}")
    
    print(f"\nOriginal text: {text}")
    
    encrypted_blocks = RSA.encrypt_string(text, public_key)
    print(f"Number of encrypted blocks: {len(encrypted_blocks)}")
    
    decrypted_text = RSA.decrypt_string(encrypted_blocks, private_key)
    print(f"Decrypted text: {decrypted_text}")
    print(f"Encryption-decryption success: {text == decrypted_text}")
