"""
时间攻击 (Timing Attack) 模拟
演示如何通过测量加密/解密操作的时间来推断密钥信息
"""

import time
import random
import statistics
from typing import List, Tuple
import matplotlib.pyplot as plt
from rsa_crypto import RSA


class TimingAttack:
    """时间攻击类"""
    
    def __init__(self):
        """初始化时间攻击"""
        self.measurements = []
    
    @staticmethod
    def measure_decryption_time(ciphertext: int, private_key: Tuple[int, int],
                               use_vulnerable: bool = True, trials: int = 100) -> List[float]:
        """
        测量解密操作的时间
        
        参数:
            ciphertext: 密文
            private_key: 私钥
            use_vulnerable: 是否使用易受攻击的版本
            trials: 测试次数
        
        返回: 时间测量列表（秒）
        """
        times = []
        
        for _ in range(trials):
            start = time.perf_counter()
            
            if use_vulnerable:
                RSA.decrypt_vulnerable(ciphertext, private_key)
            else:
                RSA.decrypt_secure(ciphertext, private_key)
            
            end = time.perf_counter()
            times.append(end - start)
        
        return times
    
    @staticmethod
    def analyze_timing(times: List[float]) -> dict:
        """
        分析时间数据
        
        返回: 统计信息字典
        """
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'min': min(times),
            'max': max(times),
            'count': len(times)
        }
    
    def attack_vulnerable_implementation(self, public_key: Tuple[int, int],
                                        private_key: Tuple[int, int],
                                        num_samples: int = 50):
        """
        对易受攻击的实现进行时间攻击
        
        通过测量不同输入的解密时间，尝试推断密钥信息
        """
        print("\n" + "="*80)
        print("时间攻击: 攻击易受攻击的RSA实现")
        print("="*80)
        
        print(f"\n[攻击者] 开始收集时间数据...")
        print(f"[攻击者] 将测试 {num_samples} 个不同的密文")
        
        # 收集不同密文的解密时间
        timing_data = []
        
        for i in range(num_samples):
            # 生成随机消息
            message = random.randint(1, public_key[1] - 1)
            
            # 加密
            ciphertext = RSA.encrypt(message, public_key)
            
            # 测量解密时间
            times = self.measure_decryption_time(ciphertext, private_key,
                                                use_vulnerable=True, trials=20)
            avg_time = statistics.mean(times)
            
            timing_data.append({
                'message': message,
                'ciphertext': ciphertext,
                'avg_time': avg_time,
                'times': times
            })
            
            if (i + 1) % 10 == 0:
                print(f"[攻击者] 已收集 {i + 1}/{num_samples} 个样本...")
        
        self.measurements = timing_data
        
        # 分析时间差异
        print(f"\n[攻击者] 数据收集完成，开始分析...")
        
        all_times = [d['avg_time'] for d in timing_data]
        stats = self.analyze_timing(all_times)
        
        print(f"\n时间统计:")
        print(f"  平均时间: {stats['mean']*1e6:.2f} 微秒")
        print(f"  中位数: {stats['median']*1e6:.2f} 微秒")
        print(f"  标准差: {stats['stdev']*1e6:.2f} 微秒")
        print(f"  最小值: {stats['min']*1e6:.2f} 微秒")
        print(f"  最大值: {stats['max']*1e6:.2f} 微秒")
        print(f"  时间范围: {(stats['max'] - stats['min'])*1e6:.2f} 微秒")
        
        # 检测时间变化
        time_variance = stats['stdev'] / stats['mean'] * 100 if stats['mean'] > 0 else 0
        
        print(f"\n[攻击者] 分析结果:")
        print(f"  时间变异系数: {time_variance:.2f}%")
        
        if time_variance > 5:
            print(f"  ⚠ 检测到明显的时间差异！")
            print(f"  → 该实现容易受到时间攻击")
            print(f"  → 攻击者可能通过分析时间模式推断密钥信息")
        else:
            print(f"  ✓ 时间差异较小")
            print(f"  → 该实现相对安全")
        
        return timing_data
    
    def compare_implementations(self, public_key: Tuple[int, int],
                              private_key: Tuple[int, int],
                              num_tests: int = 30):
        """
        比较易受攻击和安全的实现
        """
        print("\n" + "="*80)
        print("比较易受攻击的实现 vs 安全的实现")
        print("="*80)
        
        # 测试数据
        test_messages = [random.randint(1, public_key[1] - 1) for _ in range(num_tests)]
        
        vulnerable_times = []
        secure_times = []
        
        print("\n[测试] 收集时间数据...")
        
        for i, message in enumerate(test_messages):
            # 加密
            ciphertext = RSA.encrypt(message, public_key)
            
            # 测量易受攻击版本
            v_times = self.measure_decryption_time(ciphertext, private_key,
                                                   use_vulnerable=True, trials=10)
            vulnerable_times.extend(v_times)
            
            # 测量安全版本
            s_times = self.measure_decryption_time(ciphertext, private_key,
                                                   use_vulnerable=False, trials=10)
            secure_times.extend(s_times)
            
            if (i + 1) % 10 == 0:
                print(f"[测试] 已测试 {i + 1}/{num_tests} 个样本...")
        
        # 分析结果
        print("\n" + "="*80)
        print("统计结果")
        print("="*80)
        
        v_stats = self.analyze_timing(vulnerable_times)
        s_stats = self.analyze_timing(secure_times)
        
        print("\n易受攻击的实现:")
        print(f"  平均时间: {v_stats['mean']*1e6:.2f} 微秒")
        print(f"  标准差: {v_stats['stdev']*1e6:.2f} 微秒")
        print(f"  变异系数: {v_stats['stdev']/v_stats['mean']*100:.2f}%")
        
        print("\n安全的实现:")
        print(f"  平均时间: {s_stats['mean']*1e6:.2f} 微秒")
        print(f"  标准差: {s_stats['stdev']*1e6:.2f} 微秒")
        print(f"  变异系数: {s_stats['stdev']/s_stats['mean']*100:.2f}%")
        
        print("\n" + "="*80)
        print("结论")
        print("="*80)
        
        v_cv = v_stats['stdev'] / v_stats['mean'] * 100
        s_cv = s_stats['stdev'] / s_stats['mean'] * 100
        
        print(f"易受攻击实现的时间变化: {v_cv:.2f}%")
        print(f"安全实现的时间变化: {s_cv:.2f}%")
        
        if s_cv < v_cv:
            improvement = (v_cv - s_cv) / v_cv * 100
            print(f"\n✓ 安全实现减少了 {improvement:.1f}% 的时间变化")
            print(f"  → 更难通过时间攻击获取信息")
        
        return {
            'vulnerable': v_stats,
            'secure': s_stats,
            'vulnerable_times': vulnerable_times,
            'secure_times': secure_times
        }
    
    def visualize_timing_attack(self, comparison_data: dict = None):
        """可视化时间攻击数据"""
        try:
            print("\n[可视化] 生成时间分布图...")
            
            if comparison_data:
                plt.figure(figsize=(12, 5))
                
                # 易受攻击的实现
                plt.subplot(1, 2, 1)
                times_us = [t * 1e6 for t in comparison_data['vulnerable_times']]
                plt.hist(times_us, bins=30, color='red', alpha=0.7, edgecolor='black')
                plt.xlabel('解密时间 (微秒)')
                plt.ylabel('频数')
                plt.title('易受攻击的实现 - 时间分布')
                plt.axvline(statistics.mean(times_us), color='darkred',
                           linestyle='--', linewidth=2, label=f'平均值: {statistics.mean(times_us):.2f}μs')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                # 安全的实现
                plt.subplot(1, 2, 2)
                times_us = [t * 1e6 for t in comparison_data['secure_times']]
                plt.hist(times_us, bins=30, color='green', alpha=0.7, edgecolor='black')
                plt.xlabel('解密时间 (微秒)')
                plt.ylabel('频数')
                plt.title('安全的实现 - 时间分布')
                plt.axvline(statistics.mean(times_us), color='darkgreen',
                           linestyle='--', linewidth=2, label=f'平均值: {statistics.mean(times_us):.2f}μs')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                plt.tight_layout()
                plt.savefig('timing_attack_comparison.png', dpi=150, bbox_inches='tight')
                print("[可视化] 图表已保存到: timing_attack_comparison.png")
                
            elif self.measurements:
                plt.figure(figsize=(10, 6))
                times_us = [d['avg_time'] * 1e6 for d in self.measurements]
                plt.scatter(range(len(times_us)), times_us, alpha=0.6)
                plt.xlabel('样本编号')
                plt.ylabel('平均解密时间 (微秒)')
                plt.title('时间攻击: 不同密文的解密时间')
                plt.axhline(statistics.mean(times_us), color='r',
                           linestyle='--', label=f'平均值: {statistics.mean(times_us):.2f}μs')
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.savefig('timing_attack_data.png', dpi=150, bbox_inches='tight')
                print("[可视化] 图表已保存到: timing_attack_data.png")
            
        except Exception as e:
            print(f"[警告] 无法生成图表: {e}")
            print("       (需要安装 matplotlib: pip install matplotlib)")


def demo_timing_attack_basics():
    """演示基本的时间攻击"""
    print("\n" + "="*80)
    print("演示1: 基本时间攻击原理")
    print("="*80)
    
    print("""
时间攻击原理:
1. 不同的密钥位会导致不同的计算时间
2. 攻击者通过大量测量，统计分析时间差异
3. 从时间模式中推断密钥的某些位

例如，在模幂运算中:
- 如果密钥某位为1，需要额外的乘法运算
- 如果密钥某位为0，跳过该乘法运算
- 时间差异虽然很小（微秒级），但通过统计可以检测
""")


def demo_timing_attack_vulnerable():
    """演示对易受攻击实现的攻击"""
    print("\n" + "="*80)
    print("演示2: 对易受攻击的RSA实现进行时间攻击")
    print("="*80)
    
    # 生成RSA密钥
    print("\n[系统] 生成RSA密钥...")
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keys()
    
    # 创建攻击者
    attacker = TimingAttack()
    
    # 执行时间攻击
    attacker.attack_vulnerable_implementation(public_key, private_key, num_samples=30)
    
    # 可视化
    attacker.visualize_timing_attack()


def demo_timing_attack_comparison():
    """演示易受攻击vs安全实现的比较"""
    print("\n" + "="*80)
    print("演示3: 比较易受攻击的实现和安全的实现")
    print("="*80)
    
    # 生成RSA密钥
    print("\n[系统] 生成RSA密钥...")
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keys()
    
    # 创建攻击者
    attacker = TimingAttack()
    
    # 比较两种实现
    comparison = attacker.compare_implementations(public_key, private_key, num_tests=20)
    
    # 可视化
    attacker.visualize_timing_attack(comparison)


def demo_timing_attack_prevention():
    """演示如何防御时间攻击"""
    print("\n" + "="*80)
    print("防御时间攻击的方法")
    print("="*80)
    
    print("""
1. 使用常量时间算法
   - 确保操作时间不依赖于密钥或数据
   - 避免条件分支依赖于秘密数据
   
2. 添加随机延迟
   - 在操作中加入随机等待时间
   - 使时间测量更加不可预测
   
3. 使用Blinding技术
   - 在解密前对密文进行随机化
   - 解密后去除随机化
   - 使时间与原始密文无关
   
4. 硬件级别的防护
   - 使用专用的加密硬件
   - 硬件实现常量时间操作
   
5. 批处理
   - 将多个操作打包处理
   - 固定每批的处理时间
   
6. 避免短路求值
   - 比较操作时，总是比较完整个数据
   - 不要在发现第一个不匹配时就返回
   
本演示中的安全实现采用了:
- Python内置的pow()函数（经过优化，更安全）
- 添加随机延迟
- 这些方法显著降低了时间攻击的成功率
""")


if __name__ == "__main__":
    print("="*80)
    print("时间攻击 (Timing Attack) 演示")
    print("="*80)
    
    # 演示1: 基本原理
    demo_timing_attack_basics()
    
    # 演示2: 攻击易受攻击的实现
    demo_timing_attack_vulnerable()
    
    # 演示3: 比较实现
    demo_timing_attack_comparison()
    
    # 演示4: 防御方法
    demo_timing_attack_prevention()

