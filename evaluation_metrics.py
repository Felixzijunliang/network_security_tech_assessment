import time
import statistics
from typing import Dict, List, Callable, Any
import matplotlib.pyplot as plt
import matplotlib
from dataclasses import dataclass

# Configure matplotlib for Chinese character support
matplotlib.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'DejaVu Sans', 'SimHei', 'Microsoft YaHei']
matplotlib.rcParams['axes.unicode_minus'] = False


@dataclass
class AttackMetrics:
    """Attack Evaluation Metrics"""
    attack_name: str
    success_rate: float  # Success rate (0-1)
    average_time: float  # Average time (seconds)
    complexity: str  # Complexity description
    prerequisites: List[str]  # Prerequisites
    impact: str  # Attack impact
    detectability: str  # Detectability


@dataclass
class DefenseMetrics:
    """Defense Evaluation Metrics"""
    defense_name: str
    effectiveness: float  # Effectiveness (0-1)
    performance_overhead: float  # Performance overhead (0-1)
    implementation_complexity: str  # Implementation complexity
    cost: str  # Cost
    coverage: List[str]  # Attack types defended against


class MetricsEvaluator:
    """Unified Evaluation Metrics System"""
    
    def __init__(self):
        self.results = []
    
    def measure_execution_time(self, func: Callable, trials: int = 10, *args, **kwargs) -> Dict:
        """
        测量函数执行时间
        
        Args:
            func: 要测量的函数
            trials: 测试次数
            *args, **kwargs: 函数参数
            
        Returns:
            时间统计字典
        """
        times = []
        
        for _ in range(trials):
            start = time.perf_counter()
            try:
                func(*args, **kwargs)
                elapsed = time.perf_counter() - start
                times.append(elapsed)
            except Exception as e:
                print(f"警告: 执行出错 - {e}")
                continue
        
        if not times:
            return None
        
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'min': min(times),
            'max': max(times),
            'samples': len(times)
        }
    
    def measure_success_rate(self, attack_func: Callable, trials: int = 100, *args, **kwargs) -> float:
        """
        测量攻击成功率
        
        Args:
            attack_func: 攻击函数（应返回 bool 表示成功/失败）
            trials: 测试次数
            
        Returns:
            成功率 (0-1)
        """
        successes = 0
        
        for _ in range(trials):
            try:
                result = attack_func(*args, **kwargs)
                if result:
                    successes += 1
            except:
                continue
        
        return successes / trials if trials > 0 else 0
    
    def compare_implementations(self, implementations: Dict[str, Callable], test_data: Any, trials: int = 10) -> Dict:
        """
        对比不同实现的性能
        
        Args:
            implementations: {"名称": 函数} 字典
            test_data: 测试数据
            trials: 测试次数
            
        Returns:
            对比结果
        """
        results = {}
        
        for name, func in implementations.items():
            metrics = self.measure_execution_time(func, trials, test_data)
            if metrics:
                results[name] = metrics
        
        return results
    
    @staticmethod
    def print_metrics_table(metrics_list: List[Dict], title: str = "评估指标"):
        """打印格式化的指标表格"""
        print(f"\n{title}")
        
        if not metrics_list:
            print("无数据")
            return
        
        # 表头
        headers = list(metrics_list[0].keys())
        
        # 打印表头
        header_row = " | ".join(f"{h:<15}" for h in headers)
        print(header_row)
        
        # 打印数据
        for metrics in metrics_list:
            row = " | ".join(f"{str(v):<15}" for v in metrics.values())
            print(row)
    
    @staticmethod
    def visualize_comparison(data: Dict[str, float], title: str, ylabel: str, filename: str = None):
        """
        可视化对比数据
        
        Args:
            data: {"标签": 值} 字典
            title: 图表标题
            ylabel: Y 轴标签
            filename: 保存文件名（可选）
        """
        try:
            plt.figure(figsize=(10, 6))
            
            labels = list(data.keys())
            values = list(data.values())
            
            colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8']
            bars = plt.bar(labels, values, color=colors[:len(labels)], alpha=0.8, edgecolor='black')
            
            plt.xlabel('Method', fontsize=12)
            plt.ylabel(ylabel, fontsize=12)
            plt.title(title, fontsize=14, fontweight='bold')
            plt.xticks(rotation=15, ha='right')
            plt.grid(axis='y', alpha=0.3)
            
            # 在柱状图上显示数值
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height:.2f}',
                        ha='center', va='bottom', fontsize=10)
            
            plt.tight_layout()
            
            if filename:
                plt.savefig(filename, dpi=150, bbox_inches='tight')
                print(f"[Visualization] Chart saved: {filename}")
            else:
                plt.show()
                
        except Exception as e:
            print(f"Warning: Unable to generate chart - {e}")
    
    @staticmethod
    def create_comparison_table(data: Dict[str, Dict], filename: str = None):
        """
        创建详细的对比表格
        
        Args:
            data: {"方法名": {"指标": 值}} 嵌套字典
            filename: 保存文件名（可选）
        """
        try:
            methods = list(data.keys())
            metrics = list(data[methods[0]].keys())
            
            fig, ax = plt.subplots(figsize=(12, 6))
            ax.axis('tight')
            ax.axis('off')
            
            # 准备表格数据
            table_data = []
            table_data.append(['Method'] + metrics)
            
            for method in methods:
                row = [method] + [f"{data[method][m]:.2f}" if isinstance(data[method][m], (int, float))
                                 else str(data[method][m]) for m in metrics]
                table_data.append(row)
            
            # 创建表格
            table = ax.table(cellText=table_data, cellLoc='center', loc='center',
                           colWidths=[0.2] + [0.15] * len(metrics))
            
            table.auto_set_font_size(False)
            table.set_fontsize(10)
            table.scale(1, 2)
            
            # 设置表头样式
            for i in range(len(table_data[0])):
                table[(0, i)].set_facecolor('#4ECDC4')
                table[(0, i)].set_text_props(weight='bold', color='white')
            
            # 设置交替行颜色
            for i in range(1, len(table_data)):
                color = '#f0f0f0' if i % 2 == 0 else 'white'
                for j in range(len(table_data[0])):
                    table[(i, j)].set_facecolor(color)
            
            if filename:
                plt.savefig(filename, dpi=150, bbox_inches='tight')
                print(f"[Table] Comparison table saved: {filename}")
            else:
                plt.show()
                
        except Exception as e:
            print(f"Warning: Unable to generate table - {e}")


def demo_dh_attack_metrics():
    """DH Attack Evaluation Metrics Summary"""
    print("\nDiffie-Hellman Attack Evaluation Metrics Summary")
    
    attacks = [
        AttackMetrics(
            attack_name="Man-in-the-Middle (MITM)",
            success_rate=1.0,
            average_time=0.001,
            complexity="O(1) - Real-time",
            prerequisites=["Control communication channel", "No key verification"],
            impact="Complete control of communication",
            detectability="Low (requires key verification)"
        ),
        AttackMetrics(
            attack_name="Small Subgroup Attack",
            success_rate=0.7,
            average_time=0.1,
            complexity="O(n) - n is subgroup order",
            prerequisites=["Non-safe prime", "Small subgroup exists"],
            impact="Leak partial key information",
            detectability="Medium (abnormal public key)"
        )
    ]
    
    print("\nAttack Comparison:")
    print(f"{'Attack Type':<25} {'Success Rate':<15} {'Avg Time':<15} {'Impact':<25}")
    
    for attack in attacks:
        print(f"{attack.attack_name:<25} {attack.success_rate*100:>6.1f}%        "
              f"{attack.average_time*1000:>6.2f}ms      {attack.impact:<25}")
    
    # Visualization
    print("\nGenerating visualization comparison...")
    evaluator = MetricsEvaluator()
    
    success_data = {a.attack_name: a.success_rate * 100 for a in attacks}
    evaluator.visualize_comparison(
        success_data,
        "DH Attack Success Rate Comparison",
        "Success Rate (%)",
        "dh_attack_success_comparison.png"
    )
    
    time_data = {a.attack_name: a.average_time * 1000 for a in attacks}
    evaluator.visualize_comparison(
        time_data,
        "DH Attack Time Comparison",
        "Average Time (milliseconds)",
        "dh_attack_time_comparison.png"
    )


def demo_dh_defense_metrics():
    """DH Defense Evaluation Metrics Summary"""
    print("\nDiffie-Hellman Defense Evaluation Metrics Summary")
    
    defenses = [
        DefenseMetrics(
            defense_name="Authenticated Key Exchange (HMAC)",
            effectiveness=0.95,
            performance_overhead=0.05,
            implementation_complexity="Low",
            cost="Low",
            coverage=["Man-in-the-Middle Attack"]
        ),
        DefenseMetrics(
            defense_name="Safe Prime + Public Key Verification",
            effectiveness=0.90,
            performance_overhead=0.15,
            implementation_complexity="Medium",
            cost="Medium",
            coverage=["Small Subgroup Attack"]
        ),
        DefenseMetrics(
            defense_name="Combined Defense",
            effectiveness=0.98,
            performance_overhead=0.18,
            implementation_complexity="Medium",
            cost="Medium",
            coverage=["Man-in-the-Middle Attack", "Small Subgroup Attack"]
        )
    ]
    
    print("\nDefense Method Comparison:")
    print(f"{'Defense Method':<35} {'Effectiveness':<15} {'Overhead':<15} {'Complexity':<15}")
    
    for defense in defenses:
        print(f"{defense.defense_name:<35} {defense.effectiveness*100:>6.1f}%        "
              f"{defense.performance_overhead*100:>6.1f}%        {defense.implementation_complexity:<15}")
    
    # Visualization
    print("\nGenerating defense effect comparison...")
    evaluator = MetricsEvaluator()
    
    effectiveness_data = {d.defense_name: d.effectiveness * 100 for d in defenses}
    evaluator.visualize_comparison(
        effectiveness_data,
        "DH Defense Effectiveness Comparison",
        "Effectiveness (%)",
        "dh_defense_effectiveness_comparison.png"
    )
    
    overhead_data = {d.defense_name: d.performance_overhead * 100 for d in defenses}
    evaluator.visualize_comparison(
        overhead_data,
        "DH Defense Performance Overhead Comparison",
        "Performance Overhead (%)",
        "dh_defense_overhead_comparison.png"
    )


def demo_rsa_attack_metrics():
    """RSA Attack Evaluation Metrics Summary"""
    print("\nRSA Attack Evaluation Metrics Summary")
    
    attacks = [
        AttackMetrics(
            attack_name="Timing Attack",
            success_rate=0.65,
            average_time=60.0,
            complexity="O(k * n) - k is key bits",
            prerequisites=["Vulnerable implementation", "High-precision timing"],
            impact="May leak key",
            detectability="Low"
        ),
        AttackMetrics(
            attack_name="Small Exponent Attack",
            success_rate=0.80,
            average_time=0.01,
            complexity="O(e * log n) - Fast",
            prerequisites=["Small e (e=3)", "No padding", "Small message"],
            impact="Complete ciphertext crack",
            detectability="Low"
        )
    ]
    
    print("\nAttack Comparison:")
    print(f"{'Attack Type':<30} {'Success Rate':<15} {'Avg Time':<20} {'Complexity':<30}")
    
    for attack in attacks:
        avg_time_str = f"{attack.average_time*1000:.2f}ms" if attack.average_time < 1 else f"{attack.average_time:.1f}s"
        print(f"{attack.attack_name:<30} {attack.success_rate*100:>6.1f}%        "
              f"{avg_time_str:>15}     {attack.complexity:<30}")
    
    # Visualization
    print("\nGenerating visualization comparison...")
    evaluator = MetricsEvaluator()
    
    success_data = {a.attack_name: a.success_rate * 100 for a in attacks}
    evaluator.visualize_comparison(
        success_data,
        "RSA Attack Success Rate Comparison",
        "Success Rate (%)",
        "rsa_attack_success_comparison.png"
    )


def demo_rsa_defense_metrics():
    """RSA Defense Evaluation Metrics Summary"""
    print("\nRSA Defense Evaluation Metrics Summary")
    
    defenses = [
        DefenseMetrics(
            defense_name="Constant-Time Algorithm + Random Delay",
            effectiveness=0.85,
            performance_overhead=0.20,
            implementation_complexity="Medium",
            cost="Medium",
            coverage=["Timing Attack"]
        ),
        DefenseMetrics(
            defense_name="OAEP Padding + Large e",
            effectiveness=0.99,
            performance_overhead=0.15,
            implementation_complexity="Medium",
            cost="Low",
            coverage=["Small Exponent Attack", "Chosen Ciphertext Attack"]
        ),
        DefenseMetrics(
            defense_name="Combined Defense",
            effectiveness=0.98,
            performance_overhead=0.30,
            implementation_complexity="High",
            cost="Medium",
            coverage=["Timing Attack", "Small Exponent Attack", "Chosen Ciphertext Attack"]
        )
    ]
    
    print("\nDefense Method Comparison:")
    print(f"{'Defense Method':<40} {'Effectiveness':<15} {'Overhead':<15} {'Coverage':<15}")
    
    for defense in defenses:
        coverage_str = ", ".join(defense.coverage[:2])
        if len(defense.coverage) > 2:
            coverage_str += "..."
        print(f"{defense.defense_name:<40} {defense.effectiveness*100:>6.1f}%        "
              f"{defense.performance_overhead*100:>6.1f}%        {coverage_str:<15}")
    
    # Visualization
    print("\nGenerating defense effect comparison...")
    evaluator = MetricsEvaluator()
    
    effectiveness_data = {d.defense_name: d.effectiveness * 100 for d in defenses}
    evaluator.visualize_comparison(
        effectiveness_data,
        "RSA Defense Effectiveness Comparison",
        "Effectiveness (%)",
        "rsa_defense_effectiveness_comparison.png"
    )
    
    overhead_data = {d.defense_name: d.performance_overhead * 100 for d in defenses}
    evaluator.visualize_comparison(
        overhead_data,
        "RSA Defense Performance Overhead Comparison",
        "Performance Overhead (%)",
        "rsa_defense_overhead_comparison.png"
    )


def demo_综合对比():
    """Comprehensive Comparison of All Attacks and Defenses"""
    print("\nComprehensive Attack and Defense Comparison")
    
    print("\n1. All Attack Methods Comparison")
    
    all_attacks = {
        "DH MITM Attack": {"Success Rate": 100, "Speed": 99, "Impact": 100, "Detection Difficulty": 80},
        "DH Small Subgroup": {"Success Rate": 70, "Speed": 85, "Impact": 60, "Detection Difficulty": 50},
        "RSA Timing Attack": {"Success Rate": 65, "Speed": 20, "Impact": 80, "Detection Difficulty": 90},
        "RSA Small Exponent": {"Success Rate": 80, "Speed": 95, "Impact": 100, "Detection Difficulty": 70}
    }
    
    print(f"{'Attack':<25} {'Success Rate':<15} {'Speed':<12} {'Impact':<12} {'Detection':<12}")
    for attack, metrics in all_attacks.items():
        print(f"{attack:<25} {metrics['Success Rate']:>5}%        {metrics['Speed']:>5}%     "
              f"{metrics['Impact']:>5}%     {metrics['Detection Difficulty']:>5}%")
    
    print("\n2. All Defense Methods Comparison")
    
    all_defenses = {
        "DH Authentication": {"Effectiveness": 95, "Overhead": 5, "Complexity": 30},
        "DH Safe Parameters": {"Effectiveness": 90, "Overhead": 15, "Complexity": 50},
        "RSA Timing Defense": {"Effectiveness": 85, "Overhead": 20, "Complexity": 60},
        "RSA OAEP": {"Effectiveness": 99, "Overhead": 15, "Complexity": 50}
    }
    
    print(f"{'Defense':<25} {'Effectiveness':<15} {'Overhead':<15} {'Complexity':<15}")
    for defense, metrics in all_defenses.items():
        print(f"{defense:<25} {metrics['Effectiveness']:>5}%        {metrics['Overhead']:>6}%       "
              f"{metrics['Complexity']:>6}%")
    
    print("\n3. Recommendations")
    print("  DH Best Practice: Authentication + Safe Parameters (Overall effectiveness 98%)")
    print("  RSA Best Practice: OAEP + Timing Defense (Overall effectiveness 98%)")
    print("  Best Cost-Benefit: OAEP Padding (Effectiveness 99%, Overhead only 15%)")


if __name__ == "__main__":
    print("\nUnified Evaluation Metrics System Demonstration")
    
    # Demo 1: DH Attack Metrics
    demo_dh_attack_metrics()
    
    input("\nPress Enter to continue...")
    
    # Demo 2: DH Defense Metrics
    demo_dh_defense_metrics()
    
    input("\nPress Enter to continue...")
    
    # Demo 3: RSA Attack Metrics
    demo_rsa_attack_metrics()
    
    input("\nPress Enter to continue...")
    
    # Demo 4: RSA Defense Metrics
    demo_rsa_defense_metrics()
    
    input("\nPress Enter to continue...")
    
    # Demo 5: Comprehensive Comparison
    demo_综合对比()
    
    print("\nAll evaluations completed!")

