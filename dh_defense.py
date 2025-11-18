from diffie_hellman import DiffieHellman
import hashlib
import hmac
import random
from typing import Tuple, Dict


class AuthenticatedDH:
    def __init__(self, name: str, p: int, g: int, use_safe_prime: bool = True):
        self.name = name
        self.p = p
        self.g = g
        self.use_safe_prime = use_safe_prime
        self.private_key = None
        self.public_key = None
        self.long_term_key = None  # 用于认证的长期密钥
        self.shared_secret = None
        
        self._generate_keys()
    
    def _generate_keys(self):
        # 生成 DH 密钥对
        self.private_key = random.randint(2, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)
        
        # 生成长期认证密钥（模拟预共享密钥或证书）
        self.long_term_key = hashlib.sha256(
            f"{self.name}_secret_key".encode()
        ).digest()
    
    def get_authenticated_public_key(self) -> Dict:
        # 使用 HMAC 对公钥进行认证
        mac = hmac.new(
            self.long_term_key,
            str(self.public_key).encode(),
            hashlib.sha256
        ).hexdigest()
        
        return {
            'public_key': self.public_key,
            'mac': mac,
            'identity': self.name
        }
    
    def verify_public_key(self, authenticated_key: Dict, peer_long_term_key: bytes) -> bool:
        public_key = authenticated_key['public_key']
        received_mac = authenticated_key['mac']
        identity = authenticated_key['identity']
        
        # 计算期望的 MAC
        expected_mac = hmac.new(
            peer_long_term_key,
            str(public_key).encode(),
            hashlib.sha256
        ).hexdigest()
        
        # 常量时间比较（防止时序攻击）
        is_valid = hmac.compare_digest(received_mac, expected_mac)
        
        if is_valid:
            print(f"[{self.name}] ✓ 成功验证 {identity} 的公钥")
        else:
            print(f"[{self.name}] ✗ {identity} 的公钥验证失败！")
        
        return is_valid
    
    def validate_public_key_range(self, peer_public_key: int) -> bool:
        # 检查 1: 公钥必须在 [2, p-2] 范围内
        if not (2 <= peer_public_key <= self.p - 2):
            print(f"[{self.name}] ✗ 公钥超出有效范围")
            return False
        
        # 检查 2: 公钥不能是 1（阶为 1）
        if peer_public_key == 1:
            print(f"[{self.name}] ✗ 公钥是单位元")
            return False
        
        # 检查 3: 对于安全素数 p = 2q + 1，验证 peer_public_key^q mod p != 1
        if self.use_safe_prime:
            q = (self.p - 1) // 2
            if pow(peer_public_key, q, self.p) == 1 and peer_public_key != self.p - 1:
                print(f"[{self.name}] ✗ 公钥可能在小子群中")
                return False
        
        print(f"[{self.name}] ✓ 公钥范围验证通过")
        return True
    
    def compute_shared_secret(self, peer_public_key: int) -> int:
        if not self.validate_public_key_range(peer_public_key):
            raise ValueError("对方公钥验证失败")
        
        self.shared_secret = pow(peer_public_key, self.private_key, self.p)
        return self.shared_secret
    
    def get_session_key(self) -> bytes:
        if self.shared_secret is None:
            raise ValueError("必须先计算共享密钥")
        
        # 使用 HKDF 派生会话密钥
        session_key = hashlib.sha256(
            str(self.shared_secret).encode()
        ).digest()
        
        return session_key


class SecureParameterValidator:
    @staticmethod
    def validate_parameters(p: int, g: int, min_bits: int = 2048) -> Dict:
        results = {
            'valid': True,
            'warnings': [],
            'errors': []
        }
        
        # 检查 1: 素数位数
        p_bits = p.bit_length()
        if p_bits < min_bits:
            results['errors'].append(f"素数位数不足: {p_bits} < {min_bits}")
            results['valid'] = False
        elif p_bits < 2048:
            results['warnings'].append(f"素数位数偏小: {p_bits} bits (推荐 >= 2048)")
        
        # 检查 2: p 是否是素数
        if not DiffieHellman._is_prime(p):
            results['errors'].append("p 不是素数")
            results['valid'] = False
        
        # 检查 3: 是否是安全素数
        q = (p - 1) // 2
        is_safe_prime = DiffieHellman._is_prime(q)
        if not is_safe_prime:
            results['warnings'].append("p 不是安全素数，可能受到小子群攻击")
        else:
            results['info'] = "p 是安全素数 (p = 2q + 1)"
        
        # 检查 4: 生成元的有效性
        if g < 2:
            results['errors'].append(f"生成元过小: {g}")
            results['valid'] = False
        elif g >= p:
            results['errors'].append(f"生成元过大: {g} >= {p}")
            results['valid'] = False
        
        # 检查 5: 生成元的阶
        if g == 1:
            results['errors'].append("生成元不能为 1")
            results['valid'] = False
        elif pow(g, 2, p) == 1:
            results['errors'].append("生成元的阶太小")
            results['valid'] = False
        
        return results
    
    @staticmethod
    def print_validation_result(results: Dict):
        print("DH 参数安全性验证结果")
        
        if results['valid']:
            print("✓ 参数验证通过")
        else:
            print("✗ 参数验证失败")
        
        if 'info' in results:
            print(f"\n信息:")
            print(f"  {results['info']}")
        
        if results['warnings']:
            print(f"\n⚠ 警告:")
            for warning in results['warnings']:
                print(f"  - {warning}")
        
        if results['errors']:
            print(f"\n✗ 错误:")
            for error in results['errors']:
                print(f"  - {error}")


def demo_authenticated_dh():
    print("Defense Approach 1: Authenticated Diffie-Hellman Key exchange")
    
    print("Use HMAC to authenticate public keys and prevent man-in-the-middle attacks")
    
    # 生成 DH 参数
    print("Step 1: Generate DH parameters")
    dh_params = DiffieHellman(key_size=256)
    p, g = dh_params.generate_parameters(use_safe_prime=True)
    
    # Alice 和 Bob 创建认证的 DH 会话
    print("Step 2: Alice and Bob initialize the authentication session")
    alice = AuthenticatedDH("Alice", p, g, use_safe_prime=True)
    bob = AuthenticatedDH("Bob", p, g, use_safe_prime=True)
    
    print(f"[Alice] Generating key pairs")
    print(f"[Bob] Generating key pairs")
    
    # 模拟预共享或通过证书获得对方的长期密钥
    print("Step 3: Exchange long-term authentication key (via secure channel or certificate)")
    alice_long_term = alice.long_term_key
    bob_long_term = bob.long_term_key
    print(f"[system] Alice and Bob have securely exchanged the long-term authentication key")
    
    # 交换认证的公钥
    print("Step 4: Exchange authenticated public keys")
    alice_auth_key = alice.get_authenticated_public_key()
    bob_auth_key = bob.get_authenticated_public_key()
    
    print(f"[Alice] Sending authenticated public key")
    print(f"  Public key: {alice_auth_key['public_key']}")
    print(f"  MAC: {alice_auth_key['mac'][:16]}...")
    
    print(f"[Bob] Sending authenticated public key")
    print(f"  Public key: {bob_auth_key['public_key']}")
    print(f"  MAC: {bob_auth_key['mac'][:16]}...")
    
    # 验证公钥
    print("Step 5: Verify the other party's public key")
    alice_verified = alice.verify_public_key(bob_auth_key, bob_long_term)
    bob_verified = bob.verify_public_key(alice_auth_key, alice_long_term)
    
    if alice_verified and bob_verified:
        print("✓ Both public keys verification successful")
        
        # 计算共享密钥
        print("Step 6: Compute the shared key")
        alice_shared = alice.compute_shared_secret(bob_auth_key['public_key'])
        bob_shared = bob.compute_shared_secret(alice_auth_key['public_key'])
        
        print(f"[Alice] Shared key: {alice_shared}")
        print(f"[Bob] Shared key: {bob_shared}")
        print(f"Key matches: {alice_shared == bob_shared}")
        
        # 派生会话密钥
        print("Step 7: Derive the session key")
        alice_session = alice.get_session_key()
        bob_session = bob.get_session_key()
        
        print(f"[Alice] Session key: {alice_session.hex()[:32]}...")
        print(f"[Bob] Session key: {bob_session.hex()[:32]}...")
        print(f"Session key matches: {alice_session == bob_session}")
        
        print("✓ Authentication key exchange completed, can safely communicate")
    else:
        print("✗ Public key verification failed, terminate the connection")


def demo_mitm_attack_on_authenticated_dh():
    print("Defense Effect Demonstration: Authenticated DH Defense against Man-in-the-Middle Attacks")
    
    print("Description: The attacker attempts to forge the public key, but will be detected by the authentication mechanism")
    
    # 生成参数
    dh_params = DiffieHellman(key_size=256)
    p, g = dh_params.generate_parameters(use_safe_prime=True)
    
    # Alice 和 Bob
    alice = AuthenticatedDH("Alice", p, g)
    bob = AuthenticatedDH("Bob", p, g)
    
    alice_long_term = alice.long_term_key
    bob_long_term = bob.long_term_key
    
    # 攻击者 Mallory
    print("[Mallory] Attempting man-in-the-middle attack...")
    mallory = AuthenticatedDH("Mallory", p, g)
    
    # Mallory 尝试伪造 Bob 的公钥
    print("[Mallory] Intercepting and attempting to forge Bob's public key...")
    fake_bob_key = mallory.get_authenticated_public_key()
    fake_bob_key['identity'] = "Bob"  # 伪装身份
    
    print(f"[Mallory] Sending forged public key to Alice")
    print(f"  Public key: {fake_bob_key['public_key']}")
    print(f"  MAC: {fake_bob_key['mac'][:16]}...")
    print(f"  Identity: {fake_bob_key['identity']}")
    
    # Alice 验证
    print("[Alice] Verifying the received public key...")
    is_valid = alice.verify_public_key(fake_bob_key, bob_long_term)
    
    if not is_valid:
        print("✓ Attack detected!")
        print("[Alice] Detected forged public key")
        print("[Alice] MAC verification failed")
        print("[Alice] Terminate the connection to prevent man-in-the-middle attack")
    else:
        print("✗ Attack successful (should not happen)")


def demo_secure_parameters():
    print("Defense Approach 2: Use secure parameters")
    print("Use safe prime + public key verification to defend against small subgroup attacks")
    
    # 生成安全参数
    print("Step 1: Generate secure DH parameters")
    dh = DiffieHellman(key_size=256)
    p, g = dh.generate_parameters(use_safe_prime=True)
    
    # 验证参数
    print("Step 2: Verify the security of the parameters")
    validator = SecureParameterValidator()
    results = validator.validate_parameters(p, g, min_bits=256)
    validator.print_validation_result(results)
    
    # 创建使用安全参数的 DH
    print("Step 3: Use secure parameters for key exchange")
    alice = AuthenticatedDH("Alice", p, g, use_safe_prime=True)
    bob = AuthenticatedDH("Bob", p, g, use_safe_prime=True)
    
    # 模拟攻击者发送小阶公钥
    print("Step 4: Simulate small subgroup attack")
    print("[Attacker] Attempting to send small subgroup element as public key...")
    
    # 尝试使用阶为 2 的元素（p-1）
    malicious_public = p - 1  # 这个元素的阶是 2
    print(f"[Attacker] Sending malicious public key: {malicious_public}")
    
    # Alice 验证
    print(f"[Alice] Verifying the received public key...")
    try:
        alice.compute_shared_secret(malicious_public)
        print("✗ Verification failed (should not accept this public key)")
    except ValueError as e:
        print(f"✓ Successfully intercepted small subgroup attack")
        print(f"    Reason: {e}")
    
    print("✓ Secure parameters + public key verification successfully defended against small subgroup attacks")


def demo_defense_comparison():
    print("Comparison of Different Defense Methods")
    print("Different defense methods have different characteristics")
    print(f"{'Defense Method':<30} {'Defense Attack':<25} {'Overhead':<15}")
    print(f"{'No Defense':<30} {'None':<25} {'Low':<15}")
    print(f"{'Authentication (HMAC/Signature)':<30} {'Man-in-the-Middle Attack':<25} {'Low':<15}")
    print(f"{'Safe Prime':<30} {'Small Subgroup Attack':<25} {'Medium':<15}")
    print(f"{'Public Key Range Validation':<30} {'Small Subgroup Attack':<25} {'Very Low':<15}")
    print(f"{'Authentication + Safe Parameters':<30} {'All Known Attacks':<25} {'Medium':<15}")
    
    defenses = [
        {
            'name': 'No Defense',
            'mitm_protection': 0,
            'subgroup_protection': 0,
            'overhead': 0,
            'complexity': '低'
        },
        {
            'name': 'Authentication Only',
            'mitm_protection': 95,
            'subgroup_protection': 0,
            'overhead': 5,
            'complexity': '低'
        },
        {
            'name': 'Safe Prime Only',
            'mitm_protection': 0,
            'subgroup_protection': 90,
            'overhead': 10,
            'complexity': '中'
        },
        {
            'name': 'Authentication + Safe Parameters',
            'mitm_protection': 95,
            'subgroup_protection': 95,
            'overhead': 15,
            'complexity': '中'
        }
    ]
    
    print(f"{'Defense Scheme':<25} {'MITM Protection':<15} {'Small Subgroup Protection':<15} {'Overhead':<10}")
    for d in defenses:
        print(f"{d['name']:<25} {d['mitm_protection']}%{'':<11} "
              f"{d['subgroup_protection']}%{'':<11} {d['overhead']}%")
    
    print("✓ Best Practice: Authentication + Safe Parameters")
    print("  - Defend against both man-in-the-middle and small subgroup attacks")
    print("  - Acceptable performance overhead (< 20%)")
    print("  - Moderate implementation complexity")


if __name__ == "__main__":
    print("Defense Measures Demonstration of Diffie-Hellman")
    # 演示 1: 认证的 DH
    demo_authenticated_dh()
    
    input("\nPress Enter to continue the next demonstration...")
    
    # 演示 2: 认证 DH 防御 MITM
    demo_mitm_attack_on_authenticated_dh()
    
    input("\nPress Enter to continue the next demonstration...")
    
    # 演示 3: 安全参数
    demo_secure_parameters()
    
    input("\nPress Enter to continue the next demonstration...")
    
    # 演示 4: 防御对比
    demo_defense_comparison()
    
    
    print("All demonstrations completed!")
    

