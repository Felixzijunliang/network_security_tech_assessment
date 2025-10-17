"""
快速演示脚本
展示项目的核心功能（5分钟快速演示）
"""

def print_section(title):
    """打印分节标题"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def demo_quick():
    """快速演示所有功能"""
    
    print("\n" + "="*70)
    print("  网络安全技术大作业 - 5分钟快速演示")
    print("="*70)
    
    # 演示1: 哈夫曼编码
    print_section("1. 哈夫曼编码演示")
    try:
        from huffman import HuffmanCoding
        
        huffman = HuffmanCoding()
        text = "hello world! 网络安全技术"
        print(f"\n原始文本: {text}")
        print(f"原始大小: {len(text)} 字符 ({len(text.encode('utf-8')) * 8} 比特)")
        
        encoded, codes = huffman.encode(text)
        print(f"压缩后: {len(encoded)} 比特")
        print(f"压缩率: {huffman.get_compression_ratio(text, encoded):.1f}%")
        
        decoded = huffman.decode(encoded)
        print(f"解码验证: {'✓ 成功' if text == decoded else '✗ 失败'}")
        
    except Exception as e:
        print(f"错误: {e}")
    
    # 演示2: RSA加密
    print_section("2. RSA加密演示")
    try:
        from rsa_crypto import RSA
        
        print("\n生成RSA密钥（256位，快速演示）...")
        rsa = RSA(key_size=256)
        public_key, private_key = rsa.generate_keys()
        
        message = "机密信息"
        print(f"\n原始消息: {message}")
        
        encrypted = RSA.encrypt_string(message, public_key)
        print(f"加密完成: {len(encrypted)} 个密文块")
        
        decrypted = RSA.decrypt_string(encrypted, private_key)
        print(f"解密结果: {decrypted}")
        print(f"验证: {'✓ 成功' if message == decrypted else '✗ 失败'}")
        
    except Exception as e:
        print(f"错误: {e}")
    
    # 演示3: 安全通信
    print_section("3. 安全通信演示（压缩+加密）")
    try:
        from secure_communication import SecureCommunication
        
        print("\n初始化Alice和Bob的通信系统...")
        alice_comm = SecureCommunication(rsa_key_size=256)
        bob_comm = SecureCommunication(rsa_key_size=256)
        
        alice_comm.setup_keys()
        bob_comm.setup_keys()
        
        alice_public = alice_comm.get_public_key()
        bob_public = bob_comm.get_public_key()
        
        message = "这是一条秘密消息，将被压缩和加密"
        print(f"\n[Alice] 发送消息: {message}")
        
        # 发送
        transmission = alice_comm.send_message(message, bob_public)
        
        # 接收
        print("\n[Bob] 接收并解密消息...")
        received = bob_comm.receive_message(transmission)
        
        print(f"\n[Bob] 收到消息: {received}")
        print(f"完整性验证: {'✓ 成功' if message == received else '✗ 失败'}")
        
    except Exception as e:
        print(f"错误: {e}")
    
    # 演示4: 中间人攻击
    print_section("4. 中间人攻击演示")
    try:
        from secure_communication import CommunicationParty
        from mitm_attack import ManInTheMiddle
        
        print("\n场景: 攻击者Mallory劫持了Alice和Bob的密钥交换")
        
        alice = CommunicationParty("Alice", key_size=256)
        bob = CommunicationParty("Bob", key_size=256)
        mallory = ManInTheMiddle("Mallory")
        
        alice_public = alice.get_public_key()
        bob_public = bob.get_public_key()
        mallory_public = mallory.get_public_key()
        
        mallory.intercept_key_exchange(alice_public, bob_public)
        
        message = "转账金额: $1000"
        print(f"\n[Alice] 原始消息: {message}")
        
        # Alice用攻击者的公钥加密（以为是Bob的）
        transmission = alice.send_to(message, mallory_public)
        
        # 攻击者拦截、解密、修改、重新加密
        modified = mallory.intercept_decrypt_modify_encrypt(
            transmission, "Alice", "Bob",
            alice_public, bob_public
        )
        
        # Bob接收被篡改的消息
        received = bob.receive_from(modified)
        
        print(f"\n[Bob] 收到消息: {received}")
        print(f"\n⚠️  消息已被篡改！")
        print(f"防御方法: 使用数字证书验证公钥的真实性")
        
    except Exception as e:
        print(f"错误: {e}")
    
    # 演示5: 时间攻击
    print_section("5. 时间攻击演示")
    try:
        from timing_attack import TimingAttack
        from rsa_crypto import RSA
        import statistics
        
        print("\n比较易受攻击和安全的RSA实现...")
        
        rsa = RSA(key_size=256)
        public_key, private_key = rsa.generate_keys()
        
        # 生成测试数据
        message = 12345
        ciphertext = RSA.encrypt(message, public_key)
        
        # 测量易受攻击版本
        print("\n测量易受攻击的实现...")
        v_times = TimingAttack.measure_decryption_time(
            ciphertext, private_key, use_vulnerable=True, trials=20
        )
        v_avg = statistics.mean(v_times) * 1e6
        v_std = statistics.stdev(v_times) * 1e6
        
        # 测量安全版本
        print("测量安全的实现...")
        s_times = TimingAttack.measure_decryption_time(
            ciphertext, private_key, use_vulnerable=False, trials=20
        )
        s_avg = statistics.mean(s_times) * 1e6
        s_std = statistics.stdev(s_times) * 1e6
        
        print(f"\n结果对比:")
        print(f"易受攻击版本: {v_avg:.2f} ± {v_std:.2f} 微秒")
        print(f"安全版本:     {s_avg:.2f} ± {s_std:.2f} 微秒")
        
        v_cv = (v_std / v_avg) * 100
        s_cv = (s_std / s_avg) * 100
        
        print(f"\n时间变异系数:")
        print(f"易受攻击版本: {v_cv:.2f}%")
        print(f"安全版本:     {s_cv:.2f}%")
        
        if s_cv < v_cv:
            improvement = ((v_cv - s_cv) / v_cv) * 100
            print(f"\n✓ 安全实现减少了 {improvement:.1f}% 的时间变化")
            print(f"  更难通过时间攻击推断密钥信息")
        
    except Exception as e:
        print(f"错误: {e}")
    
    # 总结
    print("\n" + "="*70)
    print("  演示完成")
    print("="*70)
    print("""
演示内容总结:
✓ 哈夫曼编码 - 数据压缩
✓ RSA加密 - 非对称加密
✓ 安全通信 - 端到端加密
✓ 中间人攻击 - 密钥劫持攻击
✓ 时间攻击 - 侧信道攻击

运行完整演示: python main.py
运行测试: python quick_test.py
查看文档: README.md 和 使用指南.md
""")


if __name__ == "__main__":
    demo_quick()

