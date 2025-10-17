"""
安全通信系统
结合哈夫曼编码和RSA加密实现安全的消息传输
"""

from huffman import HuffmanCoding
from rsa_crypto import RSA
from typing import Tuple, Dict
import json


class SecureCommunication:
    """安全通信类"""
    
    def __init__(self, rsa_key_size: int = 512):
        """
        初始化安全通信系统
        参数:
            rsa_key_size: RSA密钥大小
        """
        self.huffman = HuffmanCoding()
        self.rsa = RSA(key_size=rsa_key_size)
        self.public_key = None
        self.private_key = None
    
    def setup_keys(self):
        """生成密钥对"""
        print("\n[安全通信] 正在初始化加密系统...")
        self.public_key, self.private_key = self.rsa.generate_keys()
        print("[安全通信] 密钥生成完成")
    
    def get_public_key(self) -> Tuple[int, int]:
        """获取公钥"""
        return self.public_key
    
    def send_message(self, message: str, receiver_public_key: Tuple[int, int]) -> Dict:
        """
        发送消息（压缩 + 加密）
        
        流程:
        1. 使用哈夫曼编码压缩消息
        2. 使用RSA加密压缩后的数据
        
        参数:
            message: 原始消息
            receiver_public_key: 接收方的公钥
        
        返回: 包含加密数据和元数据的字典
        """
        print("\n[发送方] 准备发送消息...")
        print(f"[发送方] 原始消息: {message}")
        print(f"[发送方] 原始长度: {len(message)} 字符")
        
        # 步骤1: 哈夫曼编码压缩
        print("\n[发送方] 步骤1: 使用哈夫曼编码压缩...")
        encoded_bits, huffman_codes = self.huffman.encode(message)
        print(f"[发送方] 压缩后: {len(encoded_bits)} 比特")
        compression_ratio = self.huffman.get_compression_ratio(message, encoded_bits)
        print(f"[发送方] 压缩率: {compression_ratio:.2f}%")
        
        # 将二进制字符串转换为整数进行加密
        # 为了处理大消息，我们需要分块
        print("\n[发送方] 步骤2: 使用RSA加密...")
        
        # 将编码后的比特串和哈夫曼编码表打包
        package = {
            'encoded_bits': encoded_bits,
            'huffman_codes': huffman_codes
        }
        package_str = json.dumps(package)
        
        # RSA加密
        encrypted_blocks = RSA.encrypt_string(package_str, receiver_public_key)
        print(f"[发送方] 加密完成，生成 {len(encrypted_blocks)} 个加密块")
        
        # 创建传输包
        transmission = {
            'encrypted_blocks': encrypted_blocks,
            'sender': 'Alice',
            'receiver': 'Bob'
        }
        
        print("[发送方] 消息发送完成")
        return transmission
    
    def receive_message(self, transmission: Dict) -> str:
        """
        接收消息（解密 + 解压）
        
        流程:
        1. 使用RSA私钥解密
        2. 使用哈夫曼编码解压
        
        参数:
            transmission: 传输包
        
        返回: 原始消息
        """
        print("\n[接收方] 收到加密消息...")
        
        # 步骤1: RSA解密
        print("[接收方] 步骤1: 使用RSA解密...")
        encrypted_blocks = transmission['encrypted_blocks']
        print(f"[接收方] 收到 {len(encrypted_blocks)} 个加密块")
        
        decrypted_str = RSA.decrypt_string(encrypted_blocks, self.private_key)
        
        # 解包
        package = json.loads(decrypted_str)
        encoded_bits = package['encoded_bits']
        huffman_codes = package['huffman_codes']
        
        print(f"[接收方] 解密完成，得到 {len(encoded_bits)} 比特的压缩数据")
        
        # 步骤2: 哈夫曼解码
        print("[接收方] 步骤2: 使用哈夫曼编码解压...")
        decoded_message = self.huffman.decode(encoded_bits, huffman_codes)
        print(f"[接收方] 解压完成，恢复消息: {decoded_message}")
        
        return decoded_message


class CommunicationParty:
    """通信参与方"""
    
    def __init__(self, name: str, key_size: int = 512):
        """
        初始化通信方
        参数:
            name: 参与方名称
            key_size: RSA密钥大小
        """
        self.name = name
        self.comm = SecureCommunication(rsa_key_size=key_size)
        print(f"\n{'='*60}")
        print(f"[{self.name}] 初始化通信系统")
        print(f"{'='*60}")
        self.comm.setup_keys()
    
    def get_public_key(self) -> Tuple[int, int]:
        """获取公钥"""
        return self.comm.get_public_key()
    
    def send_to(self, message: str, receiver_public_key: Tuple[int, int]) -> Dict:
        """发送消息给其他方"""
        print(f"\n{'='*60}")
        print(f"[{self.name}] 发送消息")
        print(f"{'='*60}")
        return self.comm.send_message(message, receiver_public_key)
    
    def receive_from(self, transmission: Dict) -> str:
        """接收消息"""
        print(f"\n{'='*60}")
        print(f"[{self.name}] 接收消息")
        print(f"{'='*60}")
        return self.comm.receive_message(transmission)


if __name__ == "__main__":
    print("\n" + "="*60)
    print("安全通信系统演示")
    print("="*60)
    
    # 创建两个通信方：Alice和Bob
    alice = CommunicationParty("Alice", key_size=512)
    bob = CommunicationParty("Bob", key_size=512)
    
    # 交换公钥
    print("\n" + "="*60)
    print("交换公钥")
    print("="*60)
    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()
    print(f"[Alice] 公钥已共享")
    print(f"[Bob] 公钥已共享")
    
    # Alice发送消息给Bob
    message = "Hello Bob! This is a secret message from Alice. Let's test the secure communication system with Huffman coding and RSA encryption!"
    
    transmission = alice.send_to(message, bob_public)
    
    # Bob接收消息
    received_message = bob.receive_from(transmission)
    
    # 验证
    print("\n" + "="*60)
    print("验证结果")
    print("="*60)
    print(f"原始消息: {message}")
    print(f"接收消息: {received_message}")
    print(f"消息完整性: {'✓ 成功' if message == received_message else '✗ 失败'}")

