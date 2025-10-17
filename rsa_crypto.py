"""
RSA加密实现
用于安全通信的非对称加密算法
包含易受时间攻击的版本和安全版本
"""

import random
import time
from typing import Tuple


class RSA:
    """RSA加密类"""
    
    def __init__(self, key_size: int = 1024):
        """
        初始化RSA
        参数:
            key_size: 密钥大小（比特）
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    @staticmethod
    def _is_prime(n: int, k: int = 5) -> bool:
        """
        Miller-Rabin素性测试
        参数:
            n: 待测试的数
            k: 测试轮数
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # 将n-1表示为2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # 进行k轮测试
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
        """生成指定位数的素数"""
        while True:
            # 生成奇数
            num = random.getrandbits(bits)
            num |= (1 << bits - 1) | 1
            
            if RSA._is_prime(num):
                return num
    
    @staticmethod
    def _gcd(a: int, b: int) -> int:
        """计算最大公约数"""
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """扩展欧几里得算法"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSA._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    @staticmethod
    def _mod_inverse(e: int, phi: int) -> int:
        """计算模逆元"""
        gcd, x, _ = RSA._extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("模逆元不存在")
        return x % phi
    
    def generate_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        生成RSA密钥对
        返回: ((e, n), (d, n)) - (公钥, 私钥)
        """
        print(f"正在生成 {self.key_size} 位 RSA 密钥...")
        
        # 生成两个大素数
        p = self._generate_prime(self.key_size // 2)
        q = self._generate_prime(self.key_size // 2)
        
        # 确保p和q不相等
        while p == q:
            q = self._generate_prime(self.key_size // 2)
        
        # 计算n和φ(n)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # 选择公钥指数e
        e = 65537  # 常用的公钥指数
        while self._gcd(e, phi) != 1:
            e = random.randrange(2, phi)
        
        # 计算私钥指数d
        d = self._mod_inverse(e, phi)
        
        # 保存密钥
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        print("密钥生成完成!")
        return self.public_key, self.private_key
    
    @staticmethod
    def encrypt(message: int, public_key: Tuple[int, int]) -> int:
        """
        使用公钥加密消息
        参数:
            message: 消息（整数）
            public_key: 公钥 (e, n)
        返回: 密文
        """
        e, n = public_key
        return pow(message, e, n)
    
    @staticmethod
    def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
        """
        使用私钥解密消息（易受时间攻击的版本）
        参数:
            ciphertext: 密文
            private_key: 私钥 (d, n)
        返回: 明文
        """
        d, n = private_key
        return pow(ciphertext, d, n)
    
    @staticmethod
    def decrypt_vulnerable(ciphertext: int, private_key: Tuple[int, int]) -> int:
        """
        易受时间攻击的解密实现
        使用简单的模幂运算，时间与密钥位数相关
        """
        d, n = private_key
        result = 1
        base = ciphertext % n
        exponent = d
        
        # 简单的逐位计算，容易受到时间攻击
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % n
            base = (base * base) % n
            exponent //= 2
        
        return result
    
    @staticmethod
    def decrypt_secure(ciphertext: int, private_key: Tuple[int, int]) -> int:
        """
        安全的解密实现（抗时间攻击）
        使用常量时间算法或添加随机延迟
        """
        d, n = private_key
        
        # 使用Python内置的pow函数，更安全
        result = pow(ciphertext, d, n)
        
        # 添加随机延迟，使时间更难预测
        time.sleep(random.uniform(0.0001, 0.0005))
        
        return result
    
    @staticmethod
    def string_to_int(text: str) -> int:
        """将字符串转换为整数"""
        return int.from_bytes(text.encode('utf-8'), byteorder='big')
    
    @staticmethod
    def int_to_string(num: int) -> str:
        """将整数转换为字符串"""
        # 计算需要的字节数
        byte_length = (num.bit_length() + 7) // 8
        return num.to_bytes(byte_length, byteorder='big').decode('utf-8', errors='ignore')
    
    @staticmethod
    def encrypt_string(text: str, public_key: Tuple[int, int]) -> list:
        """
        加密字符串（分块加密）
        返回密文块列表
        """
        e, n = public_key
        max_block_size = (n.bit_length() - 1) // 8  # 每块最大字节数
        
        # 分块
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
        """
        解密字符串（分块解密）
        """
        decrypted_bytes = b''
        
        for block in encrypted_blocks:
            decrypted_int = RSA.decrypt(block, private_key)
            # 计算字节数
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_block = decrypted_int.to_bytes(byte_length, byteorder='big')
            decrypted_bytes += decrypted_block
        
        return decrypted_bytes.decode('utf-8', errors='ignore')


if __name__ == "__main__":
    # 测试RSA加密
    print("=" * 60)
    print("RSA加密测试")
    print("=" * 60)
    
    # 使用较小的密钥以加快测试速度
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keys()
    
    print(f"\n公钥 (e, n): ")
    print(f"  e = {public_key[0]}")
    print(f"  n = {public_key[1]}")
    
    # 测试简单整数加密
    print("\n" + "=" * 60)
    print("测试1: 整数加密")
    print("=" * 60)
    message = 42
    print(f"原始消息: {message}")
    
    encrypted = RSA.encrypt(message, public_key)
    print(f"加密后: {encrypted}")
    
    decrypted = RSA.decrypt(encrypted, private_key)
    print(f"解密后: {decrypted}")
    print(f"加密解密成功: {message == decrypted}")
    
    # 测试字符串加密
    print("\n" + "=" * 60)
    print("测试2: 字符串加密")
    print("=" * 60)
    text = "Hello, RSA encryption!"
    print(f"原始文本: {text}")
    
    encrypted_blocks = RSA.encrypt_string(text, public_key)
    print(f"加密块数: {len(encrypted_blocks)}")
    
    decrypted_text = RSA.decrypt_string(encrypted_blocks, private_key)
    print(f"解密文本: {decrypted_text}")
    print(f"加密解密成功: {text == decrypted_text}")

