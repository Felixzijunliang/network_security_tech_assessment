"""
网络安全技术大作业 - 主程序
整合哈夫曼编码、RSA加密、中间人攻击和时间攻击的演示
"""

import sys
import time


def print_header(title: str):
    """打印格式化的标题"""
    print("\n" + "="*80)
    print(title.center(80))
    print("="*80)


def print_menu():
    """打印主菜单"""
    print_header("网络安全技术演示系统")
    print("""
请选择要演示的内容:

1. 哈夫曼编码演示
   - 展示数据压缩原理
   - 编码和解码过程

2. RSA加密演示
   - 密钥生成
   - 加密和解密过程

3. 安全通信系统演示
   - 结合哈夫曼编码和RSA加密
   - 完整的端到端加密通信

4. 中间人攻击演示
   - 场景1: 失败的攻击（正确的密钥交换）
   - 场景2: 成功的攻击（攻击者控制密钥交换）
   - 防御方法

5. 时间攻击演示
   - 时间攻击原理
   - 对易受攻击实现的攻击
   - 安全实现对比
   - 防御方法

6. 完整演示（运行所有模块）

0. 退出

""")


def demo_huffman():
    """哈夫曼编码演示"""
    print_header("哈夫曼编码演示")
    
    try:
        from huffman import HuffmanCoding
        
        huffman = HuffmanCoding()
        text = "hello world! this is a demonstration of huffman coding for data compression."
        
        print(f"\n原始文本: {text}")
        print(f"原始大小: {len(text)} 字符 ({len(text) * 8} 比特)")
        
        # 编码
        encoded, codes = huffman.encode(text)
        print(f"\n编码后大小: {len(encoded)} 比特")
        print(f"压缩率: {huffman.get_compression_ratio(text, encoded):.2f}%")
        
        # 显示部分编码表
        print("\n部分哈夫曼编码表:")
        print("-" * 40)
        for i, (char, code) in enumerate(sorted(codes.items())[:10]):
            print(f"'{char}': {code}")
        if len(codes) > 10:
            print(f"... 还有 {len(codes) - 10} 个字符")
        print("-" * 40)
        
        # 解码
        decoded = huffman.decode(encoded)
        print(f"\n解码验证: {'✓ 成功' if text == decoded else '✗ 失败'}")
        
    except Exception as e:
        print(f"\n错误: {e}")
    
    input("\n按回车键继续...")


def demo_rsa():
    """RSA加密演示"""
    print_header("RSA加密演示")
    
    try:
        from rsa_crypto import RSA
        
        print("\n初始化RSA系统 (512位密钥)...")
        rsa = RSA(key_size=512)
        public_key, private_key = rsa.generate_keys()
        
        print(f"\n公钥 (e, n):")
        print(f"  e = {public_key[0]}")
        print(f"  n的位数 = {public_key[1].bit_length()} 位")
        
        # 测试消息
        message = "Hello, RSA!"
        print(f"\n原始消息: {message}")
        
        # 加密
        encrypted_blocks = RSA.encrypt_string(message, public_key)
        print(f"加密后: {len(encrypted_blocks)} 个密文块")
        
        # 解密
        decrypted = RSA.decrypt_string(encrypted_blocks, private_key)
        print(f"解密后: {decrypted}")
        
        print(f"\n加密解密验证: {'✓ 成功' if message == decrypted else '✗ 失败'}")
        
    except Exception as e:
        print(f"\n错误: {e}")
    
    input("\n按回车键继续...")


def demo_secure_communication():
    """安全通信系统演示"""
    print_header("安全通信系统演示")
    
    try:
        from secure_communication import CommunicationParty
        
        print("\n初始化通信系统...")
        alice = CommunicationParty("Alice", key_size=512)
        bob = CommunicationParty("Bob", key_size=512)
        
        # 交换公钥
        print("\n" + "="*80)
        print("交换公钥")
        print("="*80)
        alice_public = alice.get_public_key()
        bob_public = bob.get_public_key()
        print("[Alice] 公钥已共享")
        print("[Bob] 公钥已共享")
        
        # 发送消息
        message = "Hello Bob! This is a secret message that will be compressed and encrypted."
        transmission = alice.send_to(message, bob_public)
        
        # 接收消息
        received = bob.receive_from(transmission)
        
        # 验证
        print("\n" + "="*80)
        print("验证")
        print("="*80)
        print(f"消息完整性: {'✓ 成功' if message == received else '✗ 失败'}")
        
    except Exception as e:
        print(f"\n错误: {e}")
    
    input("\n按回车键继续...")


def demo_mitm_attack():
    """中间人攻击演示"""
    print_header("中间人攻击演示")
    
    try:
        from mitm_attack import demo_failed_mitm_attack, demo_successful_mitm_attack, demo_prevention
        
        print("\n将演示两个场景:")
        print("1. 失败的中间人攻击")
        print("2. 成功的中间人攻击")
        
        input("\n按回车键开始演示...")
        
        # 场景1
        demo_failed_mitm_attack()
        
        input("\n按回车键继续下一个场景...")
        
        # 场景2
        demo_successful_mitm_attack()
        
        # 防御方法
        demo_prevention()
        
    except Exception as e:
        print(f"\n错误: {e}")
    
    input("\n按回车键继续...")


def demo_timing_attack():
    """时间攻击演示"""
    print_header("时间攻击演示")
    
    try:
        from timing_attack import (demo_timing_attack_basics,
                                   demo_timing_attack_vulnerable,
                                   demo_timing_attack_comparison,
                                   demo_timing_attack_prevention)
        
        print("\n将演示:")
        print("1. 时间攻击基本原理")
        print("2. 对易受攻击实现的攻击")
        print("3. 安全实现与易受攻击实现的比较")
        print("4. 防御方法")
        
        input("\n按回车键开始演示...")
        
        # 演示1: 原理
        demo_timing_attack_basics()
        
        input("\n按回车键继续...")
        
        # 演示2: 攻击
        demo_timing_attack_vulnerable()
        
        input("\n按回车键继续...")
        
        # 演示3: 比较
        demo_timing_attack_comparison()
        
        # 演示4: 防御
        demo_timing_attack_prevention()
        
    except Exception as e:
        print(f"\n错误: {e}")
    
    input("\n按回车键继续...")


def demo_all():
    """运行所有演示"""
    print_header("完整演示")
    print("\n将按顺序运行所有演示模块...")
    
    demos = [
        ("哈夫曼编码", demo_huffman),
        ("RSA加密", demo_rsa),
        ("安全通信系统", demo_secure_communication),
        ("中间人攻击", demo_mitm_attack),
        ("时间攻击", demo_timing_attack)
    ]
    
    for i, (name, func) in enumerate(demos, 1):
        print(f"\n{'='*80}")
        print(f"第 {i}/{len(demos)} 部分: {name}")
        print(f"{'='*80}")
        
        try:
            func()
        except KeyboardInterrupt:
            print("\n\n演示已中断")
            return
        except Exception as e:
            print(f"\n错误: {e}")
            input("\n按回车键继续...")
    
    print_header("所有演示完成")


def main():
    """主函数"""
    while True:
        try:
            print_menu()
            choice = input("请输入选项 (0-6): ").strip()
            
            if choice == "0":
                print("\n感谢使用！再见！")
                break
            elif choice == "1":
                demo_huffman()
            elif choice == "2":
                demo_rsa()
            elif choice == "3":
                demo_secure_communication()
            elif choice == "4":
                demo_mitm_attack()
            elif choice == "5":
                demo_timing_attack()
            elif choice == "6":
                demo_all()
            else:
                print("\n无效的选项，请重新选择。")
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\n\n程序已中断。再见！")
            break
        except Exception as e:
            print(f"\n发生错误: {e}")
            input("\n按回车键继续...")


if __name__ == "__main__":
    main()

