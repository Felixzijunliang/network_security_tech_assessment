import random
import time
from typing import Tuple


class DiffieHellman:
    
    def __init__(self, key_size: int = 512):
        self.key_size = key_size
        self.p = None  # 大素数
        self.g = None  # 生成元
        self.private_key = None
        self.public_key = None
    
    @staticmethod
    def _is_prime(n: int, k: int = 5) -> bool:
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # 将 n-1 表示为 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # 进行 k 轮测试
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
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1  # 确保是奇数
            
            if DiffieHellman._is_prime(num):
                return num
    
    @staticmethod
    def _generate_safe_prime(bits: int, max_attempts: int = 100) -> int:
        print(f"[DH] Generating {bits} bit safe prime (this may take some time)...")
        
        for attempt in range(max_attempts):
            # 生成候选的 q
            q = DiffieHellman._generate_prime(bits - 1)
            p = 2 * q + 1
            
            # 检查 p 是否也是素数
            if DiffieHellman._is_prime(p):
                print(f"[DH] ✓ Found safe prime after {attempt + 1} attempts")
                return p
        
        # 如果找不到安全素数，退回到普通素数
        print(f"[DH] ⚠ Unable to generate safe prime, using normal prime")
        return DiffieHellman._generate_prime(bits)
    
    @staticmethod
    def _find_primitive_root(p: int) -> int:
        # 对于安全素数，通常 2, 3, 5 等小数字就是本原根
        # 为了简化，我们先尝试这些常见值
        candidates = [2, 3, 5, 7, 11]
        
        for g in candidates:
            if g >= p:
                continue
            # 简单验证：检查 g^2 和 g^q 是否不等于 1 (mod p)
            q = (p - 1) // 2
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                return g
        
        # 如果上述候选都不行，返回 2（对大多数安全素数有效）
        return 2
    
    def generate_parameters(self, use_safe_prime: bool = False):
        print(f"\n[DH] Generating Diffie-Hellman parameters...")
        print(f"[DH] Key size: {self.key_size} bits")
        
        start_time = time.time()
        
        if use_safe_prime:
            # 生成安全素数
            self.p = self._generate_safe_prime(self.key_size)
        else:
            # 生成普通素数
            self.p = self._generate_prime(self.key_size)
        
        # 找到生成元
        self.g = self._find_primitive_root(self.p)
        
        elapsed = time.time() - start_time
        
        print(f"[DH] ✓ Parameters generated (time: {elapsed:.2f} seconds)")
        print(f"[DH] p (prime) bits: {self.p.bit_length()} bits")
        print(f"[DH] g (generator): {self.g}")
        
        return self.p, self.g
    
    def generate_private_key(self) -> int:
        if self.p is None:
            raise ValueError("Must generate DH parameters (p, g) first")
        
        # 私钥应该是 [2, p-2] 范围内的随机数
        self.private_key = random.randint(2, self.p - 2)
        return self.private_key
    
    def generate_public_key(self) -> int:
        if self.private_key is None:
            raise ValueError("Must generate private key first")
        
        # Public key = g^private key mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key: int) -> int:
        if self.private_key is None:
            raise ValueError("Must generate private key first")
        
        # Shared secret = other public key^self private key mod p
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return shared_secret
    
    @staticmethod
    def create_party(name: str, p: int, g: int, key_size: int = 512):
        dh = DiffieHellman(key_size)
        dh.p = p
        dh.g = g
        dh.generate_private_key()
        dh.generate_public_key()
        return dh


def demo_basic_dh():
    print("Basic Diffie-Hellman key exchange demonstration")
    
    print("\nScenario: Alice and Bob want to establish a shared secret over an insecure channel")
    
    # 1. Generate public parameters
    print("\nStep 1: Generate public parameters (p, g)")
    dh_params = DiffieHellman(key_size=256)  # 使用较小的密钥以加快演示
    p, g = dh_params.generate_parameters()
    
    # 2. Alice 生成密钥对
    print("\nStep 2: Alice generates a key pair")
    alice = DiffieHellman.create_party("Alice", p, g, key_size=256)
    print(f"[Alice] Private key (secret): {alice.private_key}")
    print(f"[Alice] Public key (public): {alice.public_key}")
    
    # 3. Bob 生成密钥对
    print("\nStep 3: Bob generates a key pair")
    bob = DiffieHellman.create_party("Bob", p, g, key_size=256)
    print(f"[Bob] Private key (secret): {bob.private_key}")
    print(f"[Bob] Public key (public): {bob.public_key}")
    
    # 4. 交换公钥
    print("\nStep 4: Alice and Bob exchange public keys")
    print(f"[Alice] Sending public key to Bob: {alice.public_key}")
    print(f"[Bob] Sending public key to Alice: {bob.public_key}")
    
    # 5. 计算共享密钥
    print("\nStep 5: Both parties compute the shared secret")
    alice_shared = alice.compute_shared_secret(bob.public_key)
    print(f"[Alice] Computed shared secret: {alice_shared}")
    
    bob_shared = bob.compute_shared_secret(alice.public_key)
    print(f"[Bob] Computed shared secret: {bob_shared}")
    
    # 6. 验证
    print("\nStep 6: Verify the shared secret")
    if alice_shared == bob_shared:
        print("✓ Success! Alice and Bob have the same shared secret")
        print(f"  Shared secret: {alice_shared}")
        print(f"  Key length: {alice_shared.bit_length()} bits")
    else:
        print("✗ Failure! Shared secret does not match")
    
    print("All demonstrations completed!")


def demo_dh_security():
    print("Diffie-Hellman security demonstration")
    
    print("\nScenario: Eve can see all public information, but cannot compute the shared secret")
    
    # 生成参数
    dh_params = DiffieHellman(key_size=256)
    p, g = dh_params.generate_parameters()
    
    # Alice 和 Bob 生成密钥
    alice = DiffieHellman.create_party("Alice", p, g, key_size=256)
    bob = DiffieHellman.create_party("Bob", p, g, key_size=256)
    
    # Eve 可以看到的信息
    print("\n[Eve] Eavesdropper can see the following public information:")
    print(f"  Prime p bits: {p.bit_length()} bits")
    print(f"  Generator g: {g}")
    print(f"  Alice's public key: {alice.public_key}")
    print(f"  Bob's public key: {bob.public_key}")
    
    # 计算共享密钥
    shared_secret = alice.compute_shared_secret(bob.public_key)
    
    print("\n[Eve] Eavesdropper cannot see:")
    print(f"  Alice's private key: *** (secret)")
    print(f"  Bob's private key: *** (secret)")
    print(f"  Shared secret: *** (secret)")
    
    print("\n[Analysis] Difficulty of the discrete logarithm problem:")
    print(f"  To derive Alice's private key from her public key, Eve needs to solve:")
    print(f"  {alice.public_key} = {g}^x mod {p}")
    print(f"  Where x is Alice's private key")
    print(f"  For large prime p, this problem is computationally infeasible")
    
    print("\n✓ Conclusion: Even if the eavesdropper can see all public information,")
    print("  it is computationally infeasible to compute the shared secret in a reasonable time")


def demo_safe_prime_vs_normal():
    print("Safe prime vs normal prime comparison")
    
    print("\n1. Use normal prime (vulnerable to small subgroup attack)")
    dh_normal = DiffieHellman(key_size=256)
    p_normal, g_normal = dh_normal.generate_parameters(use_safe_prime=False)
    
    print("\n2. Use safe prime (can defend against small subgroup attack)")
    dh_safe = DiffieHellman(key_size=256)
    p_safe, g_safe = dh_safe.generate_parameters(use_safe_prime=True)
    
    print("\nComparison results:")
    print(f"Normal prime p bits: {p_normal.bit_length()}")
    print(f"Safe prime p bits: {p_safe.bit_length()}")
    print(f"Safe prime satisfies: p = 2q + 1, where q = {(p_safe - 1) // 2}")
    print(f"Safe prime q is prime: {DiffieHellman._is_prime((p_safe - 1) // 2)}")
    
    print("\n✓ Safe prime can prevent small subgroup attack")
    print("  but slower generation speed")


if __name__ == "__main__":
    print("\nDiffie-Hellman key exchange protocol demonstration")
    
    # 演示 1：基本密钥交换
    demo_basic_dh()
    
    input("\nPress Enter to continue the next demonstration...")
    
    # 演示 2：安全性说明
    demo_dh_security()
    
    input("\nPress Enter to continue the next demonstration...")
    
    # 演示 3：安全素数对比
    demo_safe_prime_vs_normal()
    
    print("All demonstrations completed!")

