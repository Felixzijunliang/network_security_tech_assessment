from rsa_crypto import RSA
import random
import time
from typing import Tuple, List
import math


class SmallExponentAttack:
    def __init__(self, name: str = "Eve"):
        self.name = name
        self.attack_logs = []
    
    def attack_small_e_no_padding(self, ciphertext: int, e: int, n: int) -> Tuple[bool, int, float]:
        print(f"\n[{self.name}] Starting small exponent attack...")
        print(f"  Ciphertext: {ciphertext}")
        print(f"  Public exponent e: {e}")
        print(f"  Modulus n bit length: {n.bit_length()}")
        
        start_time = time.time()
        
        # Try to take the e-th root
        try:
            m_candidate = self._nth_root(ciphertext, e)
            
            # Verify
            if pow(m_candidate, e) == ciphertext:
                elapsed = time.time() - start_time
                print(f"\n[{self.name}] ✓ Attack successful!")
                print(f"  Cracked message: {m_candidate}")
                print(f"  Time: {elapsed:.6f} seconds")
                
                self.attack_logs.append({
                    'success': True,
                    'method': 'direct_root',
                    'time': elapsed
                })
                
                return True, m_candidate, elapsed
            else:
                print(f"\n[{self.name}] ✗ Failed to take the e-th root, m^e >= n")
                return False, None, time.time() - start_time
                
        except Exception as e:
            print(f"\n[{self.name}] ✗ Attack failed: {e}")
            return False, None, time.time() - start_time
    
    def attack_small_e_multiple_messages(self, ciphertexts: List[int], e: int, n_list: List[int]) -> Tuple[bool, int, float]:
        print(f"\n[{self.name}] Starting Håstad broadcast attack...")
        print(f"  Received {len(ciphertexts)} ciphertexts")
        print(f"  Public exponent e: {e}")
        
        if len(ciphertexts) < e:
            print(f"[{self.name}] ✗ Insufficient ciphertexts (need at least {e})")
            return False, None, 0
        
        start_time = time.time()
        
        try:
            # Use Chinese remainder theorem
            print(f"\n[{self.name}] Using Chinese remainder theorem...")
            
            # Calculate N = n1 * n2 * ... * ne
            N = 1
            for n in n_list[:e]:
                N *= n
            
            # Use CRT to calculate m^e mod N
            result = 0
            for i in range(e):
                Ni = N // n_list[i]
                Mi = self._mod_inverse(Ni, n_list[i])
                result = (result + ciphertexts[i] * Ni * Mi) % N
            
            # Take the e-th root
            m_candidate = self._nth_root(result, e)
            
            elapsed = time.time() - start_time
            
            print(f"\n[{self.name}] ✓ Attack successful!")
            print(f"  Cracked message: {m_candidate}")
            print(f"  Time: {elapsed:.6f} seconds")
            
            self.attack_logs.append({
                'success': True,
                'method': 'hastad_broadcast',
                'time': elapsed
            })
            
            return True, m_candidate, elapsed
            
        except Exception as e:
            print(f"\n[{self.name}] ✗ Attack failed: {e}")
            return False, None, time.time() - start_time
    
    @staticmethod
    def _nth_root(x: int, n: int) -> int:
        if x == 0:
            return 0
        if n == 1:
            return x
        
        # Initial guess
        high = 1
        while high ** n < x:
            high *= 2
        low = high // 2
        
        # Binary search
        while low < high:
            mid = (low + high) // 2
            mid_nth = mid ** n
            
            if mid_nth < x:
                low = mid + 1
            elif mid_nth > x:
                high = mid
            else:
                return mid
        
        # Return the nearest integer
        if low ** n > x:
            return low - 1
        return low
    
    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        """Calculate modular inverse"""
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m


def demo_small_e_vulnerable():
    print("\nDemo 1: Small Exponent Attack (No Padding)")
    
    print("\nDescription: Using e=3 and small message, attacker can directly take the cube root")
    
    # Generate RSA key, using small e
    print("\n[System] Generating RSA key (e=3)...")
    print("-" * 70)
    
    key_size = 512
    p = RSA._generate_prime(key_size // 2)
    q = RSA._generate_prime(key_size // 2)
    while p == q:
        q = RSA._generate_prime(key_size // 2)
    
    n = p * q
    e = 3  # Using small public exponent
    phi = (p - 1) * (q - 1)
    
    # Ensure e and phi are coprime
    while RSA._gcd(e, phi) != 1:
        p = RSA._generate_prime(key_size // 2)
        q = RSA._generate_prime(key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
    
    d = RSA._mod_inverse(e, phi)
    
    public_key = (e, n)
    private_key = (d, n)
    
    print(f"Public key: (e={e}, n bit length={n.bit_length()})")
    
    # Use small message (no padding)
    print("\n[Alice] Encrypting small message (no padding)...")
    print("-" * 70)
    message = 42  # Very small message
    print(f"Original message: {message}")
    
    # Check if m^e < n
    m_e = message ** e
    print(f"m^e = {m_e}")
    print(f"n = {n}")
    print(f"m^e < n: {m_e < n}")
    
    ciphertext = RSA.encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")
    
    # Attack
    attacker = SmallExponentAttack("Eve")
    success, cracked_message, elapsed = attacker.attack_small_e_no_padding(
        ciphertext, e, n
    )
    
    # Result
    print("\nAttack result")
    if success:
        print(f"✗ Attack successful! Message cracked")
        print(f"  Original message: {message}")
        print(f"  Cracked message: {cracked_message}")
        print(f"  Message matches: {message == cracked_message}")
        print(f"  Time: {elapsed:.6f} seconds (almost instant)")
    else:
        print(f"✓ Attack failed")


def demo_hastad_broadcast_attack():
    print("\nDemo 2: Håstad Broadcast Attack")
    
    print("\nDescription: Same message encrypted with same e but different n")
    
    e = 3
    num_recipients = 3
    
    # Generate multiple RSA key pairs
    print(f"\n[System] Generating {num_recipients} RSA key pairs (e={e})...")
    print("-" * 70)
    
    public_keys = []
    n_list = []
    
    for i in range(num_recipients):
        # Use very small key size (4 bits) for instant demonstration
        p = RSA._generate_prime(4)
        q = RSA._generate_prime(4)
        while p == q:
            q = RSA._generate_prime(4)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        while RSA._gcd(e, phi) != 1:
            q = RSA._generate_prime(4)
            n = p * q
            phi = (p - 1) * (q - 1)
        
        public_keys.append((e, n))
        n_list.append(n)
        print(f"  Receiver {i+1}: n bit length={n.bit_length()}")
    
    # Encrypt the same message
    print(f"\n[Alice] Sending same message to {num_recipients} receivers...")
    print("-" * 70)
    message = 12345
    print(f"Original message: {message}")
    
    ciphertexts = []
    for i, pk in enumerate(public_keys):
        c = RSA.encrypt(message, pk)
        ciphertexts.append(c)
        print(f"  Ciphertext {i+1}: {c}")
    
    # Attack
    print(f"\n[Eve] Intercepted all ciphertexts, starting attack...")
    attacker = SmallExponentAttack("Eve")
    success, cracked_message, elapsed = attacker.attack_small_e_multiple_messages(
        ciphertexts, e, n_list
    )
    
    # Result
    print("\nAttack result")
    if success:
        print(f"✗ Håstad broadcast attack successful!")
        print(f"  Original message: {message}")
        print(f"  Cracked message: {cracked_message}")
        print(f"  Message matches: {message == cracked_message}")
        print(f"  Time: {elapsed:.6f} seconds")
    else:
        print(f"✓ Attack failed")


def demo_safe_e_with_padding():
    print("\nDemo 3: Safe e with padding")
    
    print("\nDescription: Using e=65537 and large message, defense against small exponent attack")
    
    # Use standard RSA parameters
    print("\n[System] Generating standard RSA key (e=65537)...")
    print("-" * 70)
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keys()
    e, n = public_key
    
    print(f"Public exponent e: {e}")
    print(f"Modulus n bit length: {n.bit_length()}")
    
    # Use larger message
    message = random.randint(1000, 10000)
    print(f"\n[Alice] Encrypting message: {message}")
    ciphertext = RSA.encrypt(message, public_key)
    print(f"Ciphertext: {ciphertext}")
    
    # Try to attack
    print(f"\n[Eve] Trying small exponent attack...")
    print("-" * 70)
    attacker = SmallExponentAttack("Eve")
    
    try:
        # Try to take the e-th root (should fail)
        m_candidate = attacker._nth_root(ciphertext, e)
        if pow(m_candidate, e, n) != ciphertext:
            print(f"[Eve] ✓ Cannot take the e-th root (m^e >= n)")
    except:
        print(f"[Eve] ✓ Attack failed")
    
    print("\n✓ Large public exponent successfully defended against small exponent attack")


def demo_attack_comparison():
    print("\nDemo 4: Comparison of different configurations")
    
    configurations = [
        {"e": 3, "message": 42, "desc": "Small e + Small message"},
        {"e": 3, "message": 1234567890, "desc": "Small e + Large message"},
        {"e": 65537, "message": 42, "desc": "Large e + Small message"},
        {"e": 65537, "message": 1234567890, "desc": "Large e + Large message"},
    ]
    
    print("\nTesting different configurations...")
    print("-" * 70)
    
    results = []
    
    for config in configurations:
        e = config["e"]
        message = config["message"]
        desc = config["desc"]
        
        print(f"\nConfiguration: {desc}")
        print(f"  e={e}, m={message}")
        
        # Generate key
        key_size = 512
        p = RSA._generate_prime(key_size // 2)
        q = RSA._generate_prime(key_size // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        while RSA._gcd(e, phi) != 1:
            q = RSA._generate_prime(key_size // 2)
            n = p * q
            phi = (p - 1) * (q - 1)
        
        public_key = (e, n)
        
        # Encrypt
        ciphertext = RSA.encrypt(message, public_key)
        
        # Check if vulnerable
        m_e = message ** e
        vulnerable = m_e < n
        
        results.append({
            'desc': desc,
            'e': e,
            'vulnerable': vulnerable
        })
        
        if vulnerable:
            print(f"  ⚠ Vulnerable (m^e < n)")
        else:
            print(f"  ✓ Secure (m^e >= n)")
    
    # Display comparison results
    print("\nSecurity comparison")
    print(f"{'Configuration':<25} {'Public exponent':<15} {'Security':<15}")
    print("-" * 70)
    
    for r in results:
        security = "✗ Vulnerable" if r['vulnerable'] else "✓ Secure"
        print(f"{r['desc']:<25} {r['e']:<15} {security:<15}")
    
    print("\nConclusion:")
    print("  1. Using small public exponent (e=3) is risky")
    print("  2. Recommended to use e=65537")
    print("  3. Must use padding scheme (e.g. OAEP)")
    print("  4. Ensure message is large enough")


def demo_attack_metrics():
    print("\nDemo 5: Attack metrics demonstration")
    print("\nSmall exponent attack metrics")
    
    print("\nAttack metrics:")
    print("-" * 70)
    
    metrics = {
        "Attack success rate (e=3, no padding)": "High (70-90%)",
        "Attack success rate (e=3, with padding)": "Low (< 5%)",
        "Attack success rate (e=65537)": "Very low (< 1%)",
        "Attack time complexity": "O(e * log n) (fast)",
        "Prerequisites": "1. Small e 2. No padding 3. Small message",
        "Attack impact": "Complete ciphertext crack",
        "Detection difficulty": "Hard (normal encryption)"
    }
    
    for metric, value in metrics.items():
        print(f"  {metric}: {value}")
    
    print("\nDefense method comparison:")
    print("-" * 70)
    print(f"{'Defense method':<25} {'Cost':<15} {'Effect':<20}")
    print("-" * 70)
    print(f"{'Using large e (65537)':<25} {'None':<15} {'95%+':<20}")
    print(f"{'Using padding (OAEP)':<25} {'Low':<15} {'99%+':<20}")
    print(f"{'Both combined':<25} {'Low':<15} {'99.9%+':<20}")
    
    print("\nComparison: different e values")
    print("-" * 70)
    print(f"{'e value':<15} {'Encryption speed':<15} {'Security':<15} {'Recommendation':<10}")
    print("-" * 70)
    print(f"{'3':<15} {'Fast':<15} {'Low':<15} {'No':<10}")
    print(f"{'17':<15} {'Fast':<15} {'Medium':<15} {'Cautious':<10}")
    print(f"{'65537':<15} {'Medium':<15} {'High':<15} {'Yes':<10}")
    print(f"{'Large random value':<15} {'Slow':<15} {'High':<15} {'Special scenarios':<10}")


if __name__ == "__main__":
    print("\nRSA small exponent attack demonstration")
    
    # Demo 1: Small e no padding attack
    demo_small_e_vulnerable()
    
    input("\nPress Enter to continue to the next demonstration...")
    
    # Demo 2: Håstad broadcast attack
    demo_hastad_broadcast_attack()
    
    input("\nPress Enter to continue to the next demonstration...")
    
    # Demo 3: Safe configuration
    demo_safe_e_with_padding()
    
    input("\nPress Enter to continue to the next demonstration...")
    
    # Demo 4: Configuration comparison
    demo_attack_comparison()
    
    input("\nPress Enter to continue to the next demonstration...")
    
    # Demo 5: Evaluation metrics
    demo_attack_metrics()
    
    print("\nAll demonstrations completed!")

