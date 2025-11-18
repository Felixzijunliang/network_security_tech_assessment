from diffie_hellman import DiffieHellman
from typing import Tuple, Dict
import random


class DHManInTheMiddle:
    
    
    def __init__(self, name: str = "Mallory"):
        self.name = name
        self.alice_public = None
        self.bob_public = None
        self.mallory_alice_private = None  # 用于与 Alice 通信的私钥
        self.mallory_bob_private = None    # 用于与 Bob 通信的私钥
        self.mallory_alice_public = None   # 发送给 Alice 的公钥（假装是 Bob）
        self.mallory_bob_public = None     # 发送给 Bob 的公钥（假装是 Alice）
        self.shared_with_alice = None      # 与 Alice 的共享密钥
        self.shared_with_bob = None        # 与 Bob 的共享密钥
        self.p = None
        self.g = None
        self.intercepted_messages = []
    
    def intercept_parameters(self, p: int, g: int):
        print(f"\n[{self.name}] Intercepted DH parameters:")
        print(f"  p (prime): {p.bit_length()} bits")
        print(f"  g (generator): {g}")
        self.p = p
        self.g = g
    
    def prepare_attack(self):
        print(f"\n[{self.name}] Preparing man-in-the-middle attack...")
        
        # 生成与 Alice 通信用的密钥对
        self.mallory_alice_private = random.randint(2, self.p - 2)
        self.mallory_alice_public = pow(self.g, self.mallory_alice_private, self.p)
        
        # 生成与 Bob 通信用的密钥对
        self.mallory_bob_private = random.randint(2, self.p - 2)
        self.mallory_bob_public = pow(self.g, self.mallory_bob_private, self.p)
        
        print(f"[{self.name}] ✓ Generated two key pairs")
        print(f"  Public key for impersonating Bob: {self.mallory_alice_public}")
        print(f"  Public key for impersonating Alice: {self.mallory_bob_public}")
    
    def intercept_alice_public(self, alice_public: int) -> int:
        print(f"\n[{self.name}] Intercepted Alice's public key: {alice_public}")
        self.alice_public = alice_public
        
        # 计算与 Alice 的共享密钥
        self.shared_with_alice = pow(alice_public, self.mallory_alice_private, self.p)
        
        print(f"[{self.name}] → Forwarding attacker's public key to Bob (impersonating Alice)")
        print(f"[{self.name}] ✓ Established shared key with Alice")
        
        # 返回攻击者的公钥（冒充 Bob）
        return self.mallory_alice_public
    
    def intercept_bob_public(self, bob_public: int) -> int:
        print(f"\n[{self.name}] Intercepted Bob's public key: {bob_public}")
        self.bob_public = bob_public
        
        # 计算与 Bob 的共享密钥
        self.shared_with_bob = pow(bob_public, self.mallory_bob_private, self.p)
        
        print(f"[{self.name}] → Forwarding attacker's public key to Alice (impersonating Bob)")
        print(f"[{self.name}] ✓ Established shared key with Bob")
        
        # 返回攻击者的公钥（冒充 Alice）
        return self.mallory_bob_public
    
    def decrypt_from_alice(self, encrypted_message: int) -> str:
        decrypted = encrypted_message ^ self.shared_with_alice
        message = self._int_to_message(decrypted)
        return message
    
    def decrypt_from_bob(self, encrypted_message: int) -> str:
        decrypted = encrypted_message ^ self.shared_with_bob
        message = self._int_to_message(decrypted)
        return message
    
    def encrypt_to_alice(self, message: str) -> int:
        msg_int = self._message_to_int(message)
        encrypted = msg_int ^ self.shared_with_alice
        return encrypted
    
    def encrypt_to_bob(self, message: str) -> int:
        msg_int = self._message_to_int(message)
        encrypted = msg_int ^ self.shared_with_bob
        return encrypted
    
    @staticmethod
    def _message_to_int(message: str) -> int:
        return int.from_bytes(message.encode('utf-8'), byteorder='big')
    
    @staticmethod
    def _int_to_message(num: int) -> str:
        byte_length = (num.bit_length() + 7) // 8
        return num.to_bytes(byte_length, byteorder='big').decode('utf-8', errors='ignore')
    
    def intercept_and_modify(self, encrypted_msg: int, from_party: str, to_party: str) -> Tuple[int, str, str]:
        print(f"\n[{self.name}] ⚠ Intercepted message: {from_party} → {to_party}")
        
        # 解密
        if from_party == "Alice":
            original = self.decrypt_from_alice(encrypted_msg)
        else:
            original = self.decrypt_from_bob(encrypted_msg)
        
        print(f"[{self.name}] ✓ Successfully decrypted: '{original}'")
        
        # 修改消息
        modified = self._modify_message(original)
        print(f"[{self.name}] ⚠ Modified message to: '{modified}'")
        
        # 重新加密
        if to_party == "Alice":
            new_encrypted = self.encrypt_to_alice(modified)
        else:
            new_encrypted = self.encrypt_to_bob(modified)
        
        print(f"[{self.name}] ✓ Re-encrypted and forwarded")
        
        # 记录
        self.intercepted_messages.append({
            'from': from_party,
            'to': to_party,
            'original': original,
            'modified': modified
        })
        
        return new_encrypted, original, modified
    
    def _modify_message(self, original: str) -> str:
        modifications = [
            lambda msg: msg.replace("1000", "1"),
            lambda msg: msg.replace("approve", "reject"),
            lambda msg: msg.replace("yes", "no"),
            lambda msg: msg.replace("agree", "disagree"),
            lambda msg: msg + " [TAMPERED]",
            lambda msg: "FAKE: " + msg
        ]
        
        modification = random.choice(modifications)
        return modification(original)
    
    def show_attack_summary(self):
        print(f"[{self.name}] Man-in-the-middle attack summary")
        
        print(f"\nAttack statistics:")
        print(f"  Intercepted Alice's public key: {self.alice_public}")
        print(f"  Intercepted Bob's public key: {self.bob_public}")
        print(f"  Shared key with Alice: {self.shared_with_alice}")
        print(f"  Shared key with Bob: {self.shared_with_bob}")
        print(f"  Intercepted and modified messages: {len(self.intercepted_messages)}")
        
        if self.intercepted_messages:
            print(f"\nMessage modification record:")
            for i, msg in enumerate(self.intercepted_messages, 1):
                print(f"  Message #{i}:")
                print(f"    Direction: {msg['from']} → {msg['to']}")
                print(f"    Original: '{msg['original']}'")
                print(f"    Modified: '{msg['modified']}'")


def demo_successful_mitm_attack():
    print("Scenario 1: Successful Diffie-Hellman man-in-the-middle attack")
    
    print("\nDescription: Attacker Mallory controls the key exchange process")
    print("  - Alice thinks she is communicating with Bob (actually with Mallory)")
    print("  - Bob thinks he is communicating with Alice (actually with Mallory)")
    
    # 步骤 1: 生成 DH 参数
    print("\nStep 1: Generate DH public parameters")
    dh_params = DiffieHellman(key_size=256)
    p, g = dh_params.generate_parameters()
    
    # 步骤 2: Alice 和 Bob 生成密钥
    print("\nStep 2: Alice and Bob generate their own key pairs")
    alice = DiffieHellman.create_party("Alice", p, g)
    bob = DiffieHellman.create_party("Bob", p, g)
    
    print(f"[Alice] Generated public key: {alice.public_key}")
    print(f"[Bob] Generated public key: {bob.public_key}")
    
    # 步骤 3: 攻击者拦截参数并准备攻击
    print("\nStep 3: Attacker intercepts and prepares attack")
    mallory = DHManInTheMiddle("Mallory")
    mallory.intercept_parameters(p, g)
    mallory.prepare_attack()
    
    # 步骤 4: 攻击者拦截密钥交换
    print("\nStep 4: Key exchange intercepted")
    
    # Alice 发送公钥 → 被 Mallory 拦截
    fake_bob_public = mallory.intercept_bob_public(bob.public_key)
    alice_shared = alice.compute_shared_secret(fake_bob_public)
    print(f"[Alice] Received 'Bob's public key' (actually Mallory's)")
    print(f"[Alice] Computed shared key: {alice_shared}")
    
    # Bob 发送公钥 → 被 Mallory 拦截
    fake_alice_public = mallory.intercept_alice_public(alice.public_key)
    bob_shared = bob.compute_shared_secret(fake_alice_public)
    print(f"[Bob] Received 'Alice's public key' (actually Mallory's)")
    print(f"[Bob] Computed shared key: {bob_shared}")
    
    # 步骤 5: 验证攻击成功
    print("\nStep 5: Verify attack success")
    print(f"[Analysis] Alice's shared key: {alice_shared}")
    print(f"[Analysis] Mallory's shared key with Alice: {mallory.shared_with_alice}")
    print(f"[Analysis] Key match: {alice_shared == mallory.shared_with_alice}")
    
    print(f"\n[Analysis] Bob's shared key: {bob_shared}")
    print(f"[Analysis] Mallory's shared key with Bob: {mallory.shared_with_bob}")
    print(f"[Analysis] Key match: {bob_shared == mallory.shared_with_bob}")
    
    # 步骤 6: 演示消息拦截和篡改
    print("\nStep 6: Demonstrate message interception and modification")
    
    # Alice 发送消息
    message = "Transfer $1000 to account"
    print(f"\n[Alice] Sent message: '{message}'")
    msg_int = DHManInTheMiddle._message_to_int(message)
    encrypted_msg = msg_int ^ alice_shared
    print(f"[Alice] Encrypted message: {encrypted_msg}")
    
    # Mallory 拦截、解密、修改、重新加密
    modified_encrypted, original, modified = mallory.intercept_and_modify(
        encrypted_msg, "Alice", "Bob"
    )
    
    # Bob 接收消息
    print(f"\n[Bob] Received encrypted message: {modified_encrypted}")
    decrypted_int = modified_encrypted ^ bob_shared
    received_message = DHManInTheMiddle._int_to_message(decrypted_int)
    print(f"[Bob] Decrypted message: '{received_message}'")
    
    # 结果
    print("Attack result summary")
    print(f"✗ Attack successful! Message tampered")
    print(f"  Original message: '{message}'")
    print(f"  Bob received: '{received_message}'")
    print(f"  Message tampered: {message != received_message}")
    
    mallory.show_attack_summary()


def demo_failed_mitm_attack():
    """演示失败的中间人攻击（有密钥验证）"""
    print("\nScenario 2: Failed man-in-the-middle attack (with key verification)")
    
    print("\nDescription: Alice and Bob verify key fingerprints over an out-of-band channel")
    
    # 生成参数
    dh_params = DiffieHellman(key_size=256)
    p, g = dh_params.generate_parameters()
    
    # Alice 和 Bob 生成密钥
    alice = DiffieHellman.create_party("Alice", p, g)
    bob = DiffieHellman.create_party("Bob", p, g)
    
    print(f"\n[Alice] Generated public key: {alice.public_key}")
    print(f"[Bob] Generated public key: {bob.public_key}")
    
    # 攻击者尝试攻击
    mallory = DHManInTheMiddle("Mallory")
    mallory.intercept_parameters(p, g)
    mallory.prepare_attack()
    
    print("\n[Mallory] Attempting to intercept key exchange...")
    fake_bob_public = mallory.intercept_bob_public(bob.public_key)
    fake_alice_public = mallory.intercept_alice_public(alice.public_key)
    
    # 密钥验证
    print("\nKey verification process")
    print("[Alice] Confirming Bob's public key fingerprint over the phone...")
    
    # 计算密钥指纹（简化版：取公钥的哈希）
    import hashlib
    
    alice_fingerprint_real = hashlib.sha256(str(alice.public_key).encode()).hexdigest()[:16]
    bob_fingerprint_real = hashlib.sha256(str(bob.public_key).encode()).hexdigest()[:16]
    
    fake_bob_fingerprint = hashlib.sha256(str(fake_bob_public).encode()).hexdigest()[:16]
    fake_alice_fingerprint = hashlib.sha256(str(fake_alice_public).encode()).hexdigest()[:16]
    
    print(f"[Alice] Bob's real public key fingerprint: {bob_fingerprint_real}")
    print(f"[Alice] Received public key fingerprint: {fake_bob_fingerprint}")
    print(f"[Alice] Fingerprint match: {bob_fingerprint_real == fake_bob_fingerprint}")
    
    print(f"\n[Bob] Alice's real public key fingerprint: {alice_fingerprint_real}")
    print(f"[Bob] Received public key fingerprint: {fake_alice_fingerprint}")
    print(f"[Bob] Fingerprint match: {alice_fingerprint_real == fake_alice_fingerprint}")
    
    # 检测到攻击
    if bob_fingerprint_real != fake_bob_fingerprint:
        print("✓ Detected man-in-the-middle attack!")
        print("[Alice] ⚠ Warning: Received public key fingerprint does not match!")
        print("[Alice] ⚠ Possible man-in-the-middle attack, terminating communication")
        print("[Bob] ⚠ Warning: Received public key fingerprint does not match!")
        print("[Bob] ⚠ Possible man-in-the-middle attack, terminating communication")
        print("\nConclusion: Key fingerprint verification successfully defended against man-in-the-middle attack ✓")


def demo_attack_metrics():
    print("\nDH man-in-the-middle attack evaluation metrics")
    
    print("\nEvaluation metrics:")
    
    metrics = {
        "Attack success rate": "100% (when no key verification)",
        "Attack detection rate": "0% (when no verification mechanism)",
        "Attack time complexity": "O(1) (real-time interception)",
        "Prerequisites": "Control of communication channel",
        "Attack impact": "Complete control of communication content",
        "Defense cost": "Low (only key verification required)",
        "Defense effectiveness": "100% (using certificates or out-of-band verification)"
    }
    
    for metric, value in metrics.items():
        print(f"  {metric}: {value}")
    
    print("\nComparison: with defense vs without defense")
    print(f"{'Metric':<20} {'Without defense':<20} {'With defense':<20}")
    print(f"{'Attack success rate':<20} {'100%':<20} {'0%':<20}")
    print(f"{'Message confidentiality':<20} {'Fully leaked':<20} {'Fully protected':<20}")
    print(f"{'Message integrity':<20} {'Tampered':<20} {'Verifiable':<20}")
    print(f"{'Communication overhead':<20} {'Normal':<20} {'+5-10%':<20}")


if __name__ == "__main__":
    print("\nDiffie-Hellman man-in-the-middle attack demonstration")
    demo_successful_mitm_attack()
    demo_failed_mitm_attack()
    demo_attack_metrics()

