"""
哈夫曼编码实现
用于数据压缩，在加密前减少数据量
"""

import heapq
from collections import defaultdict, Counter
from typing import Dict, Tuple


class HuffmanNode:
    """哈夫曼树节点"""
    def __init__(self, char=None, freq=0, left=None, right=None):
        self.char = char  # 字符
        self.freq = freq  # 频率
        self.left = left  # 左子节点
        self.right = right  # 右子节点
    
    def __lt__(self, other):
        """用于优先队列比较"""
        return self.freq < other.freq


class HuffmanCoding:
    """哈夫曼编码类"""
    
    def __init__(self):
        self.codes = {}  # 字符到编码的映射
        self.reverse_codes = {}  # 编码到字符的映射
    
    def _build_frequency_table(self, text: str) -> Dict[str, int]:
        """构建字符频率表"""
        return dict(Counter(text))
    
    def _build_huffman_tree(self, freq_table: Dict[str, int]) -> HuffmanNode:
        """构建哈夫曼树"""
        # 创建优先队列
        heap = []
        for char, freq in freq_table.items():
            node = HuffmanNode(char=char, freq=freq)
            heapq.heappush(heap, node)
        
        # 构建哈夫曼树
        while len(heap) > 1:
            left = heapq.heappop(heap)
            right = heapq.heappop(heap)
            
            # 创建新节点
            merged = HuffmanNode(
                freq=left.freq + right.freq,
                left=left,
                right=right
            )
            heapq.heappush(heap, merged)
        
        return heap[0] if heap else None
    
    def _generate_codes(self, node: HuffmanNode, current_code: str = ""):
        """生成哈夫曼编码"""
        if node is None:
            return
        
        # 叶子节点，保存编码
        if node.char is not None:
            self.codes[node.char] = current_code if current_code else "0"
            self.reverse_codes[current_code if current_code else "0"] = node.char
            return
        
        # 递归生成编码
        self._generate_codes(node.left, current_code + "0")
        self._generate_codes(node.right, current_code + "1")
    
    def encode(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        编码文本
        返回: (编码后的二进制字符串, 编码表)
        """
        if not text:
            return "", {}
        
        # 构建频率表
        freq_table = self._build_frequency_table(text)
        
        # 构建哈夫曼树
        root = self._build_huffman_tree(freq_table)
        
        # 生成编码
        self.codes = {}
        self.reverse_codes = {}
        if len(freq_table) == 1:
            # 特殊情况：只有一个字符
            char = list(freq_table.keys())[0]
            self.codes[char] = "0"
            self.reverse_codes["0"] = char
        else:
            self._generate_codes(root)
        
        # 编码文本
        encoded_text = ''.join(self.codes[char] for char in text)
        
        return encoded_text, self.codes
    
    def decode(self, encoded_text: str, codes: Dict[str, str] = None) -> str:
        """
        解码文本
        参数:
            encoded_text: 编码后的二进制字符串
            codes: 编码表（可选，如果未提供则使用之前的编码表）
        """
        if not encoded_text:
            return ""
        
        # 如果提供了新的编码表，更新反向编码表
        if codes:
            self.codes = codes
            self.reverse_codes = {v: k for k, v in codes.items()}
        
        # 解码
        decoded_text = []
        current_code = ""
        
        for bit in encoded_text:
            current_code += bit
            if current_code in self.reverse_codes:
                decoded_text.append(self.reverse_codes[current_code])
                current_code = ""
        
        return ''.join(decoded_text)
    
    def get_compression_ratio(self, original: str, encoded: str) -> float:
        """计算压缩率"""
        original_bits = len(original) * 8  # 假设每个字符8位
        encoded_bits = len(encoded)
        
        if original_bits == 0:
            return 0
        
        return (1 - encoded_bits / original_bits) * 100
    
    def print_codes(self):
        """打印编码表"""
        print("\n哈夫曼编码表:")
        print("-" * 40)
        for char, code in sorted(self.codes.items()):
            print(f"'{char}': {code}")
        print("-" * 40)


if __name__ == "__main__":
    # 测试哈夫曼编码
    huffman = HuffmanCoding()
    
    # 测试文本
    text = "hello world! this is a test message for huffman coding."
    print(f"原始文本: {text}")
    print(f"原始长度: {len(text)} 字符 ({len(text) * 8} 比特)")
    
    # 编码
    encoded, codes = huffman.encode(text)
    print(f"\n编码后长度: {len(encoded)} 比特")
    print(f"压缩率: {huffman.get_compression_ratio(text, encoded):.2f}%")
    
    # 打印编码表
    huffman.print_codes()
    
    # 解码
    decoded = huffman.decode(encoded)
    print(f"\n解码后文本: {decoded}")
    print(f"解码正确: {text == decoded}")

