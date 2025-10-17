"""
中间人攻击 (Man-in-the-Middle Attack) 模拟
演示攻击者如何拦截和篡改通信
"""

from secure_communication import CommunicationParty, SecureCommunication
from rsa_crypto import RSA
from typing import Dict, Tuple
import json
import random


class ManInTheMiddle:
    """中间人攻击者"""
    
    def __init__(self, name: str = "Mallory"):
        """
        初始化中间人攻击者
        参数:
            name: 攻击者名称
        """
        self.name = name
        self.comm = SecureCommunication(rsa_key_size=512)
        print(f"\n{'='*60}")
        print(f"[{self.name}] 攻击者初始化")
        print(f"{'='*60}")
        self.comm.setup_keys()
        
        # 保存截获的密钥
        self.alice_public_key = None
        self.bob_public_key = None
        self.intercepted_messages = []
    
    def get_public_key(self) -> Tuple[int, int]:
        """获取攻击者的公钥"""
        return self.comm.get_public_key()
    
    def intercept_key_exchange(self, alice_public: Tuple[int, int], bob_public: Tuple[int, int]):
        """
        拦截密钥交换过程
        攻击者假装是Bob给Alice，假装是Alice给Bob
        """
        print(f"\n{'='*60}")
        print(f"[{self.name}] 拦截密钥交换")
        print(f"{'='*60}")
        
        self.alice_public_key = alice_public
        self.bob_public_key = bob_public
        
        print(f"[{self.name}] ✓ 已截获 Alice 的公钥")
        print(f"[{self.name}] ✓ 已截获 Bob 的公钥")
        print(f"[{self.name}] ⚠ 现在可以冒充双方进行通信")
    
    def intercept_and_forward(self, transmission: Dict, from_party: str, to_party: str) -> Dict:
        """
        拦截并转发消息（不修改）
        用于演示攻击者可以看到加密的数据（但无法解密）
        
        参数:
            transmission: 传输的消息
            from_party: 发送方名称
            to_party: 接收方名称
        """
        print(f"\n{'='*60}")
        print(f"[{self.name}] 拦截消息: {from_party} -> {to_party}")
        print(f"{'='*60}")
        
        print(f"[{self.name}] 截获加密消息")
        print(f"[{self.name}] 加密块数: {len(transmission['encrypted_blocks'])}")
        
        # 保存截获的消息
        self.intercepted_messages.append({
            'from': from_party,
            'to': to_party,
            'transmission': transmission
        })
        
        print(f"[{self.name}] ⚠ 无法解密消息（没有私钥）")
        print(f"[{self.name}] → 转发给 {to_party}")
        
        return transmission
    
    def intercept_decrypt_modify_encrypt(self, transmission: Dict, from_party: str, to_party: str,
                                        sender_public: Tuple[int, int],
                                        receiver_public: Tuple[int, int]) -> Dict:
        """
        拦截、解密、修改、重新加密消息
        这是成功的中间人攻击
        
        参数:
            transmission: 原始传输
            from_party: 发送方名称
            to_party: 接收方名称
            sender_public: 发送方公钥（实际是攻击者给发送方的）
            receiver_public: 接收方公钥（实际是攻击者给接收方的）
        """
        print(f"\n{'='*60}")
        print(f"[{self.name}] 执行中间人攻击")
        print(f"{'='*60}")
        
        print(f"[{self.name}] 1. 拦截从 {from_party} 到 {to_party} 的消息")
        
        # 解密消息（使用攻击者的私钥）
        print(f"[{self.name}] 2. 使用攻击者私钥解密消息...")
        encrypted_blocks = transmission['encrypted_blocks']
        decrypted_str = RSA.decrypt_string(encrypted_blocks, self.comm.private_key)
        
        # 解包
        package = json.loads(decrypted_str)
        encoded_bits = package['encoded_bits']
        huffman_codes = package['huffman_codes']
        
        # 哈夫曼解码得到原始消息
        original_message = self.comm.huffman.decode(encoded_bits, huffman_codes)
        print(f"[{self.name}] ✓ 成功解密原始消息: {original_message}")
        
        # 修改消息
        modified_message = self._modify_message(original_message)
        print(f"[{self.name}] 3. 修改消息: {modified_message}")
        
        # 重新编码和加密，发送给真正的接收方
        print(f"[{self.name}] 4. 重新加密并发送给 {to_party}...")
        
        # 哈夫曼编码
        new_encoded_bits, new_huffman_codes = self.comm.huffman.encode(modified_message)
        
        # 打包
        new_package = {
            'encoded_bits': new_encoded_bits,
            'huffman_codes': new_huffman_codes
        }
        new_package_str = json.dumps(new_package)
        
        # 使用接收方的真实公钥加密
        new_encrypted_blocks = RSA.encrypt_string(new_package_str, receiver_public)
        
        # 创建新的传输包
        new_transmission = {
            'encrypted_blocks': new_encrypted_blocks,
            'sender': from_party,  # 伪装成原发送方
            'receiver': to_party
        }
        
        print(f"[{self.name}] ✓ 攻击成功！消息已被篡改并转发")
        
        # 保存攻击记录
        self.intercepted_messages.append({
            'from': from_party,
            'to': to_party,
            'original': original_message,
            'modified': modified_message
        })
        
        return new_transmission
    
    def _modify_message(self, original: str) -> str:
        """
        修改消息内容
        模拟攻击者篡改消息
        """
        modifications = [
            lambda msg: msg.replace("secret", "public"),
            lambda msg: msg.replace("confidential", "open"),
            lambda msg: msg.replace("$1000", "$1"),
            lambda msg: msg.replace("approved", "rejected"),
            lambda msg: msg + " [MODIFIED BY ATTACKER]",
            lambda msg: "FAKE MESSAGE: " + msg
        ]
        
        # 随机选择一种修改方式
        modification = random.choice(modifications)
        return modification(original)
    
    def show_intercepted_messages(self):
        """显示所有截获的消息"""
        print(f"\n{'='*60}")
        print(f"[{self.name}] 截获的消息记录")
        print(f"{'='*60}")
        
        for i, msg in enumerate(self.intercepted_messages, 1):
            print(f"\n消息 #{i}:")
            print(f"  从: {msg['from']}")
            print(f"  到: {msg['to']}")
            if 'original' in msg:
                print(f"  原始消息: {msg['original']}")
                print(f"  修改后: {msg['modified']}")
            else:
                print(f"  状态: 无法解密")


def demo_failed_mitm_attack():
    """
    演示失败的中间人攻击
    攻击者只能看到加密数据，但无法解密
    """
    print("\n" + "="*80)
    print("场景1: 失败的中间人攻击（正确的密钥交换）")
    print("="*80)
    print("说明: Alice 和 Bob 正确交换了彼此的公钥")
    print("     攻击者只能拦截加密数据，但无法解密")
    print("="*80)
    
    # 创建通信方
    alice = CommunicationParty("Alice", key_size=512)
    bob = CommunicationParty("Bob", key_size=512)
    mallory = ManInTheMiddle("Mallory")
    
    # 正确的密钥交换
    print("\n[系统] Alice 和 Bob 正在交换公钥...")
    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()
    
    # 攻击者尝试拦截（但只能看到加密数据）
    mallory.intercept_key_exchange(alice_public, bob_public)
    
    # Alice 发送消息给 Bob
    message = "Hello Bob! This is a secret message. The password is: SECRET123"
    print("\n[Alice] 原始消息:", message)
    
    transmission = alice.send_to(message, bob_public)
    
    # 攻击者拦截消息（但无法解密）
    transmission = mallory.intercept_and_forward(transmission, "Alice", "Bob")
    
    # Bob 接收消息
    received = bob.receive_from(transmission)
    
    # 结果
    print("\n" + "="*80)
    print("结果")
    print("="*80)
    print(f"[Bob] 接收到的消息: {received}")
    print(f"消息完整性: {'✓ 成功' if message == received else '✗ 失败'}")
    print(f"[结论] 攻击者无法解密消息，通信安全 ✓")


def demo_successful_mitm_attack():
    """
    演示成功的中间人攻击
    攻击者在密钥交换阶段介入，可以解密和修改消息
    """
    print("\n\n" + "="*80)
    print("场景2: 成功的中间人攻击（攻击者控制密钥交换）")
    print("="*80)
    print("说明: 攻击者在密钥交换阶段介入")
    print("     Alice 以为在和 Bob 通信（实际是和攻击者）")
    print("     Bob 以为在和 Alice 通信（实际是和攻击者）")
    print("="*80)
    
    # 创建通信方
    alice = CommunicationParty("Alice", key_size=512)
    bob = CommunicationParty("Bob", key_size=512)
    mallory = ManInTheMiddle("Mallory")
    
    # 获取真实公钥
    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()
    mallory_public = mallory.get_public_key()
    
    # 攻击者拦截密钥交换
    mallory.intercept_key_exchange(alice_public, bob_public)
    
    print("\n[系统] 密钥交换被攻击者控制:")
    print("  - Alice 收到的 'Bob 公钥' 实际是攻击者的公钥")
    print("  - Bob 收到的 'Alice 公钥' 实际是攻击者的公钥")
    
    # Alice 发送消息（以为发给 Bob，实际发给攻击者）
    message = "Hello Bob! The transfer amount is $1000. Please approve this confidential transaction."
    print(f"\n[Alice] 原始消息: {message}")
    
    # Alice 用攻击者的公钥加密（以为是 Bob 的公钥）
    transmission = alice.send_to(message, mallory_public)
    
    # 攻击者拦截、解密、修改、重新加密
    modified_transmission = mallory.intercept_decrypt_modify_encrypt(
        transmission, "Alice", "Bob",
        alice_public, bob_public
    )
    
    # Bob 接收消息
    received = bob.receive_from(modified_transmission)
    
    # 结果
    print("\n" + "="*80)
    print("结果")
    print("="*80)
    print(f"[Alice] 发送的消息: {message}")
    print(f"[Bob] 接收的消息: {received}")
    print(f"消息是否被篡改: {'✗ 是' if message != received else '✓ 否'}")
    print(f"[结论] 攻击者成功篡改了消息！通信不安全 ✗")
    
    # 显示攻击记录
    mallory.show_intercepted_messages()


def demo_prevention():
    """演示如何防御中间人攻击"""
    print("\n\n" + "="*80)
    print("防御中间人攻击的方法")
    print("="*80)
    
    print("""
1. 使用数字证书和公钥基础设施(PKI)
   - 通过可信的证书颁发机构(CA)验证公钥的真实性
   - 确保公钥确实属于预期的通信方

2. 使用端到端加密
   - 确保只有通信双方可以解密消息
   - 即使中间人拦截，也无法读取内容

3. 密钥指纹验证
   - 通过安全渠道（如面对面）交换公钥指纹
   - 验证收到的公钥指纹是否匹配

4. 使用安全的密钥交换协议
   - Diffie-Hellman 密钥交换
   - 带认证的密钥交换协议

5. 检测异常行为
   - 监控证书变化
   - 检测SSL/TLS降级攻击

本演示中的攻击成功是因为:
- 没有验证公钥的真实性
- Alice 和 Bob 无法确认收到的公钥确实来自对方
""")


if __name__ == "__main__":
    print("="*80)
    print("中间人攻击 (Man-in-the-Middle Attack) 演示")
    print("="*80)
    
    # 场景1: 失败的攻击
    demo_failed_mitm_attack()
    
    # 场景2: 成功的攻击
    demo_successful_mitm_attack()
    
    # 防御方法
    demo_prevention()

