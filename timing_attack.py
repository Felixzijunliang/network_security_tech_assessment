import time
import random
import statistics
from typing import List, Tuple
import matplotlib.pyplot as plt
import matplotlib
from rsa_crypto import RSA

# Configure matplotlib to support Chinese characters
matplotlib.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'DejaVu Sans', 'SimHei', 'Microsoft YaHei']
matplotlib.rcParams['axes.unicode_minus'] = False  # Fix minus sign display


class TimingAttack:
    
    def __init__(self):
        """Initialize timing attack"""
        self.measurements = []
    
    @staticmethod
    def measure_decryption_time(ciphertext: int, private_key: Tuple[int, int],
                               use_vulnerable: bool = True, trials: int = 100) -> List[float]:
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

        print("Timing Attack: Attacking Vulnerable RSA Implementation")

        
        print(f"\n[Attacker] Starting to collect timing data...")
        print(f"[Attacker] Will test {num_samples} different ciphertexts")
        
        # Collect decryption times for different ciphertexts
        timing_data = []
        
        for i in range(num_samples):
            # Generate random message
            message = random.randint(1, public_key[1] - 1)
            
            # Encrypt
            ciphertext = RSA.encrypt(message, public_key)
            
            # Measure decryption time
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
                print(f"[Attacker] Collected {i + 1}/{num_samples} samples...")
        
        self.measurements = timing_data
        
        # Analyze timing differences
        print(f"\n[Attacker] Data collection complete, analyzing...")
        
        all_times = [d['avg_time'] for d in timing_data]
        stats = self.analyze_timing(all_times)
        
        print(f"\nTiming Statistics:")
        print(f"  Mean time: {stats['mean']*1e6:.2f} microseconds")
        print(f"  Median: {stats['median']*1e6:.2f} microseconds")
        print(f"  Std dev: {stats['stdev']*1e6:.2f} microseconds")
        print(f"  Min: {stats['min']*1e6:.2f} microseconds")
        print(f"  Max: {stats['max']*1e6:.2f} microseconds")
        print(f"  Time range: {(stats['max'] - stats['min'])*1e6:.2f} microseconds")
        
        # Detect timing variation
        time_variance = stats['stdev'] / stats['mean'] * 100 if stats['mean'] > 0 else 0
        
        print(f"\n[Attacker] Analysis results:")
        print(f"  Coefficient of variation: {time_variance:.2f}%")
        
        if time_variance > 5:
            print(f"  ⚠ Detected significant timing differences!")
            print(f"  → This implementation is vulnerable to timing attacks")
            print(f"  → Attacker may infer key information by analyzing timing patterns")
        else:
            print(f"  ✓ Small timing differences")
            print(f"  → This implementation is relatively secure")
        
        return timing_data
    
    def compare_implementations(self, public_key: Tuple[int, int],
                              private_key: Tuple[int, int],
                              num_tests: int = 30):

        print("Comparing Vulnerable vs Secure Implementation")

        
        # Test data
        test_messages = [random.randint(1, public_key[1] - 1) for _ in range(num_tests)]
        
        vulnerable_times = []
        secure_times = []
        
        print("\n[Test] Collecting timing data...")
        
        for i, message in enumerate(test_messages):
            # Encrypt
            ciphertext = RSA.encrypt(message, public_key)
            
            # Measure vulnerable version
            v_times = self.measure_decryption_time(ciphertext, private_key,
                                                   use_vulnerable=True, trials=10)
            vulnerable_times.extend(v_times)
            
            # Measure secure version
            s_times = self.measure_decryption_time(ciphertext, private_key,
                                                   use_vulnerable=False, trials=10)
            secure_times.extend(s_times)
            
            if (i + 1) % 10 == 0:
                print(f"[Test] Tested {i + 1}/{num_tests} samples...")
        
        # Analyze results
        print("Statistical Results")
        
        v_stats = self.analyze_timing(vulnerable_times)
        s_stats = self.analyze_timing(secure_times)
        
        print("\nVulnerable Implementation:")
        print(f"  Mean time: {v_stats['mean']*1e6:.2f} microseconds")
        print(f"  Std dev: {v_stats['stdev']*1e6:.2f} microseconds")
        print(f"  Coefficient of variation: {v_stats['stdev']/v_stats['mean']*100:.2f}%")
        
        print("\nSecure Implementation:")
        print(f"  Mean time: {s_stats['mean']*1e6:.2f} microseconds")
        print(f"  Std dev: {s_stats['stdev']*1e6:.2f} microseconds")
        print(f"  Coefficient of variation: {s_stats['stdev']/s_stats['mean']*100:.2f}%")
        

        print("Conclusion")
        
        v_cv = v_stats['stdev'] / v_stats['mean'] * 100
        s_cv = s_stats['stdev'] / s_stats['mean'] * 100
        
        print(f"Vulnerable implementation time variation: {v_cv:.2f}%")
        print(f"Secure implementation time variation: {s_cv:.2f}%")
        
        if s_cv < v_cv:
            improvement = (v_cv - s_cv) / v_cv * 100
            print(f"\n✓ Secure implementation reduced time variation by {improvement:.1f}%")
            print(f"  → Harder to obtain information through timing attacks")
        
        return {
            'vulnerable': v_stats,
            'secure': s_stats,
            'vulnerable_times': vulnerable_times,
            'secure_times': secure_times
        }
    
    def visualize_timing_attack(self, comparison_data: dict = None):
        """Visualize timing attack data"""
        try:
            print("\n[Visualization] Generating timing distribution chart...")
            
            if comparison_data:
                plt.figure(figsize=(12, 5))
                
                # Vulnerable implementation
                plt.subplot(1, 2, 1)
                times_us = [t * 1e6 for t in comparison_data['vulnerable_times']]
                plt.hist(times_us, bins=30, color='red', alpha=0.7, edgecolor='black')
                plt.xlabel('Decryption Time (microseconds)', fontsize=10)
                plt.ylabel('Frequency', fontsize=10)
                plt.title('Vulnerable Implementation - Time Distribution', fontsize=11)
                plt.axvline(statistics.mean(times_us), color='darkred',
                           linestyle='--', linewidth=2, label=f'Mean: {statistics.mean(times_us):.2f}us')
                plt.legend(fontsize=9)
                plt.grid(True, alpha=0.3)
                
                # Secure implementation
                plt.subplot(1, 2, 2)
                times_us = [t * 1e6 for t in comparison_data['secure_times']]
                plt.hist(times_us, bins=30, color='green', alpha=0.7, edgecolor='black')
                plt.xlabel('Decryption Time (microseconds)', fontsize=10)
                plt.ylabel('Frequency', fontsize=10)
                plt.title('Secure Implementation - Time Distribution', fontsize=11)
                plt.axvline(statistics.mean(times_us), color='darkgreen',
                           linestyle='--', linewidth=2, label=f'Mean: {statistics.mean(times_us):.2f}us')
                plt.legend(fontsize=9)
                plt.grid(True, alpha=0.3)
                
                plt.tight_layout()
                plt.savefig('timing_attack_comparison.png', dpi=150, bbox_inches='tight')
                print("[Visualization] Chart saved to: timing_attack_comparison.png")
                
            elif self.measurements:
                plt.figure(figsize=(10, 6))
                times_us = [d['avg_time'] * 1e6 for d in self.measurements]
                plt.scatter(range(len(times_us)), times_us, alpha=0.6)
                plt.xlabel('Sample Number', fontsize=11)
                plt.ylabel('Average Decryption Time (microseconds)', fontsize=11)
                plt.title('Timing Attack: Decryption Time for Different Ciphertexts', fontsize=12)
                plt.axhline(statistics.mean(times_us), color='r',
                           linestyle='--', label=f'Mean: {statistics.mean(times_us):.2f}us')
                plt.legend(fontsize=10)
                plt.grid(True, alpha=0.3)
                plt.savefig('timing_attack_data.png', dpi=150, bbox_inches='tight')
                print("[Visualization] Chart saved to: timing_attack_data.png")
            
        except Exception as e:
            print(f"[Warning] Cannot generate chart: {e}")
            print("         (Need to install matplotlib: pip install matplotlib)")


def demo_timing_attack_basics():

    print("Demo 1: Basic Timing Attack Principles")
    


def demo_timing_attack_vulnerable():
    print("Demo 2: Timing Attack on Vulnerable RSA Implementation")

    
    # Generate RSA keys
    print("\n[System] Generating RSA keys...")
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keys()
    
    # Create attacker
    attacker = TimingAttack()
    
    # Execute timing attack
    attacker.attack_vulnerable_implementation(public_key, private_key, num_samples=30)
    
    # Visualize
    attacker.visualize_timing_attack()


def demo_timing_attack_comparison():
    print("Demo 3: Comparing Vulnerable and Secure Implementations")

    
    # Generate RSA keys
    print("\n[System] Generating RSA keys...")
    rsa = RSA(key_size=512)
    public_key, private_key = rsa.generate_keys()
    
    # Create attacker
    attacker = TimingAttack()
    
    # Compare two implementations
    comparison = attacker.compare_implementations(public_key, private_key, num_tests=20)
    
    # Visualize
    attacker.visualize_timing_attack(comparison)


def demo_timing_attack_prevention():
    print("Methods to Defend Against Timing Attacks")
    


if __name__ == "__main__":
    print("Timing Attack Demonstration")

    
    # Demo 1: Basic principles
    demo_timing_attack_basics()
    
    # Demo 2: Attack vulnerable implementation
    demo_timing_attack_vulnerable()
    
    # Demo 3: Compare implementations
    demo_timing_attack_comparison()
    
    # Demo 4: Prevention methods
    demo_timing_attack_prevention()
