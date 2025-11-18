import heapq
from collections import defaultdict, Counter
from typing import Dict, Tuple


class HuffmanNode:
    def __init__(self, char=None, freq=0, left=None, right=None):
        self.char = char  
        self.freq = freq  
        self.left = left  
        self.right = right  
    
    def __lt__(self, other):
        """For priority queue comparison"""
        return self.freq < other.freq


class HuffmanCoding:
    """Huffman coding class"""
    
    def __init__(self):
        self.codes = {}  
        self.reverse_codes = {}  
    
    def _build_frequency_table(self, text: str) -> Dict[str, int]:
        return dict(Counter(text))
    
    def _build_huffman_tree(self, freq_table: Dict[str, int]) -> HuffmanNode:
        """Build Huffman tree"""
        # Create priority queue
        heap = []
        for char, freq in freq_table.items():
            node = HuffmanNode(char=char, freq=freq)
            heapq.heappush(heap, node)
        
        # Build Huffman tree
        while len(heap) > 1:
            left = heapq.heappop(heap)
            right = heapq.heappop(heap)
            
            # Create new node
            merged = HuffmanNode(
                freq=left.freq + right.freq,
                left=left,
                right=right
            )
            heapq.heappush(heap, merged)
        
        return heap[0] if heap else None
    
    def _generate_codes(self, node: HuffmanNode, current_code: str = ""):
        """Generate Huffman codes"""
        if node is None:
            return
        
        # Leaf node, save code
        if node.char is not None:
            self.codes[node.char] = current_code if current_code else "0"
            self.reverse_codes[current_code if current_code else "0"] = node.char
            return
        
        # Recursively generate codes
        self._generate_codes(node.left, current_code + "0")
        self._generate_codes(node.right, current_code + "1")
    
    def encode(self, text: str) -> Tuple[str, Dict[str, str]]:
        if not text:
            return "", {}
        
        # Build frequency table
        freq_table = self._build_frequency_table(text)
        
        # Build Huffman tree
        root = self._build_huffman_tree(freq_table)
        
        # Generate codes
        self.codes = {}
        self.reverse_codes = {}
        if len(freq_table) == 1:
            # Special case: only one character
            char = list(freq_table.keys())[0]
            self.codes[char] = "0"
            self.reverse_codes["0"] = char
        else:
            self._generate_codes(root)
        
        # Encode text
        encoded_text = ''.join(self.codes[char] for char in text)
        
        return encoded_text, self.codes
    
    def decode(self, encoded_text: str, codes: Dict[str, str] = None) -> str:
        if not encoded_text:
            return ""
        
        # If new encoding table provided, update reverse codes
        if codes:
            self.codes = codes
            self.reverse_codes = {v: k for k, v in codes.items()}
        
        # Decode
        decoded_text = []
        current_code = ""
        
        for bit in encoded_text:
            current_code += bit
            if current_code in self.reverse_codes:
                decoded_text.append(self.reverse_codes[current_code])
                current_code = ""
        
        return ''.join(decoded_text)
    
    def get_compression_ratio(self, original: str, encoded: str) -> float:
        original_bits = len(original) * 8  # Assume 8 bits per character
        encoded_bits = len(encoded)
        
        if original_bits == 0:
            return 0
        
        return (1 - encoded_bits / original_bits) * 100
    
    def print_codes(self):
        print("\nHuffman Encoding Table:")
        for char, code in sorted(self.codes.items()):
            print(f"'{char}': {code}")



if __name__ == "__main__":
    # Test Huffman coding
    huffman = HuffmanCoding()
    
    # Get user input
    print("Huffman Coding Test")
    print("\nPlease enter text to compress (supports Chinese and English):")
    print("(Press Enter for default text)")
    text = input("> ").strip()
    
    if not text:
        text = "hello world! this is a test message for huffman coding. 你好世界！"
        print(f"Using default text: {text}")
    
    print(f"\nOriginal text: {text}")
    print(f"Original length: {len(text)} characters ({len(text.encode('utf-8'))} bytes, {len(text.encode('utf-8')) * 8} bits)")
    
    # Encode
    encoded, codes = huffman.encode(text)
    print(f"\nEncoded length: {len(encoded)} bits")
    print(f"Compression ratio: {huffman.get_compression_ratio(text, encoded):.2f}%")
    
    # Print encoding table
    huffman.print_codes()
    
    # Decode
    decoded = huffman.decode(encoded)
    print(f"\nDecoded text: {decoded}")
    print(f"Decoding correct: {text == decoded}")
