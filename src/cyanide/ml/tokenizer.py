
import pickle

class CharacterLevelTokenizer:
    """
    Simple Character Level Tokenizer for command obfuscation resilience.
    Maps characters to integers.
    """
    def __init__(self, max_length=512):
        self.max_length = max_length
        self.char_map = {}
        self.index_map = {}
        self.vocab_size = 0
        self.pad_token = 0
        self.unk_token = 1
        
        # Initialize with standard ASCII
        self._build_vocab()
        
    def _build_vocab(self):
        # Basic ASCII printable + some common extras
        chars = "".join([chr(i) for i in range(32, 127)])
        # Add special tokens
        self.vocab = ["<PAD>", "<UNK>"] + list(chars)
        self.char_map = {c: i for i, c in enumerate(self.vocab)}
        self.index_map = {i: c for i, c in enumerate(self.vocab)}
        self.vocab_size = len(self.vocab)
        
    def encode(self, text):
        """
        Encodes text to a list of integers with padding/truncation.
        """
        text = str(text)
        tokens = [self.char_map.get(c, self.unk_token) for c in text]
        
        # Truncate
        if len(tokens) > self.max_length:
            tokens = tokens[:self.max_length]
            
        # Pad
        if len(tokens) < self.max_length:
            tokens += [self.pad_token] * (self.max_length - len(tokens))
            
        return tokens
        
    def decode(self, tokens):
        """
        Decodes a list of integers back to text.
        """
        chars = []
        for t in tokens:
            if t == self.pad_token:
                continue
            chars.append(self.index_map.get(t, ""))
        return "".join(chars)
        
    def save(self, path):
        with open(path, 'wb') as f:
            pickle.dump({
                'char_map': self.char_map,
                'index_map': self.index_map,
                'max_length': self.max_length
            }, f)
            
    def load(self, path):
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.char_map = data['char_map']
            self.index_map = data['index_map']
            self.max_length = data['max_length']
            self.vocab_size = len(self.char_map)
