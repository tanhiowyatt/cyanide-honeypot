import pickle

from cyanide.core import security


class CharacterLevelTokenizer:
    """
    Simple Character Level Tokenizer for command obfuscation resilience.
    Maps characters to integers.
    """

    # Function 140: Initializes the class instance and its attributes.
    def __init__(self, max_length=512):
        self.max_length = max_length
        self.char_map = {}
        self.index_map = {}
        self.vocab_size = 0
        self.pad_token = 0
        self.unk_token = 1

        self._build_vocab()

    # Function 141: Performs operations related to build vocab.
    def _build_vocab(self):
        chars = "".join([chr(i) for i in range(32, 127)])
        self.vocab = ["<PAD>", "<UNK>"] + list(chars)
        self.char_map = {c: i for i, c in enumerate(self.vocab)}
        self.index_map = {i: c for i, c in enumerate(self.vocab)}
        self.vocab_size = len(self.vocab)

    # Function 142: Performs operations related to encode.
    def encode(self, text):
        """
        Encodes text to a list of integers with padding/truncation.
        """
        text = str(text)
        tokens = [self.char_map.get(c, self.unk_token) for c in text]

        if len(tokens) > self.max_length:
            tokens = tokens[: self.max_length]

        if len(tokens) < self.max_length:
            tokens += [self.pad_token] * (self.max_length - len(tokens))

        return tokens

    # Function 143: Performs operations related to decode.
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

    # Function 144: Performs operations related to save.
    def save(self, path):
        with open(path, "wb") as f:
            pickle.dump(
                {
                    "char_map": self.char_map,
                    "index_map": self.index_map,
                    "max_length": self.max_length,
                },
                f,
            )

    # Function 145: Performs operations related to load.
    def load(self, path):
        with open(path, "rb") as f:
            data = security.load(f)
            self.char_map = data["char_map"]
            self.index_map = data["index_map"]
            self.max_length = data["max_length"]
            self.vocab_size = len(self.char_map)
