"""
快速测试脚本
用于验证所有模块是否正常工作
"""

import sys


def test_huffman():
    """测试哈夫曼编码"""
    print("\n" + "="*60)
    print("测试哈夫曼编码...")
    print("="*60)
    
    try:
        from huffman import HuffmanCoding
        
        huffman = HuffmanCoding()
        text = "hello world"
        
        # 编码
        encoded, codes = huffman.encode(text)
        # 解码
        decoded = huffman.decode(encoded)
        
        assert text == decoded, "解码失败"
        print("✓ 哈夫曼编码测试通过")
        return True
    except Exception as e:
        print(f"✗ 哈夫曼编码测试失败: {e}")
        return False


def test_rsa():
    """测试RSA加密"""
    print("\n" + "="*60)
    print("测试RSA加密...")
    print("="*60)
    
    try:
        from rsa_crypto import RSA
        
        # 使用较小的密钥以加快测试
        rsa = RSA(key_size=256)
        public_key, private_key = rsa.generate_keys()
        
        # 测试整数加密
        message = 42
        encrypted = RSA.encrypt(message, public_key)
        decrypted = RSA.decrypt(encrypted, private_key)
        
        assert message == decrypted, "整数加密解密失败"
        
        # 测试字符串加密
        text = "Test"
        encrypted_blocks = RSA.encrypt_string(text, public_key)
        decrypted_text = RSA.decrypt_string(encrypted_blocks, private_key)
        
        assert text == decrypted_text, "字符串加密解密失败"
        
        print("✓ RSA加密测试通过")
        return True
    except Exception as e:
        print(f"✗ RSA加密测试失败: {e}")
        return False


def test_secure_communication():
    """测试安全通信"""
    print("\n" + "="*60)
    print("测试安全通信系统...")
    print("="*60)
    
    try:
        from secure_communication import CommunicationParty
        
        # 创建通信方
        alice = CommunicationParty("Alice", key_size=256)
        bob = CommunicationParty("Bob", key_size=256)
        
        # 交换公钥
        alice_public = alice.get_public_key()
        bob_public = bob.get_public_key()
        
        # 发送消息
        message = "Test message"
        transmission = alice.send_to(message, bob_public)
        received = bob.receive_from(transmission)
        
        assert message == received, "消息传输失败"
        
        print("✓ 安全通信系统测试通过")
        return True
    except Exception as e:
        print(f"✗ 安全通信系统测试失败: {e}")
        return False


def test_imports():
    """测试所有模块是否可以导入"""
    print("\n" + "="*60)
    print("测试模块导入...")
    print("="*60)
    
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
    """运行所有测试"""
    print("\n" + "="*60)
    print("网络安全技术项目 - 快速测试")
    print("="*60)
    
    tests = [
        ("模块导入", test_imports),
        ("哈夫曼编码", test_huffman),
        ("RSA加密", test_rsa),
        ("安全通信", test_secure_communication)
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n测试 '{name}' 发生错误: {e}")
            results.append((name, False))
    
    # 总结
    print("\n" + "="*60)
    print("测试总结")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"{name}: {status}")
    
    print(f"\n总计: {passed}/{total} 测试通过")
    
    if passed == total:
        print("\n🎉 所有测试通过！项目已准备就绪。")
        return 0
    else:
        print(f"\n⚠️ {total - passed} 个测试失败。")
        return 1


if __name__ == "__main__":
    sys.exit(main())

