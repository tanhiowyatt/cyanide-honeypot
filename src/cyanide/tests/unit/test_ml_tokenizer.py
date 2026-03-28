from cyanide.ml.tokenizer import CharacterLevelTokenizer


def test_tokenizer_init():
    tokenizer = CharacterLevelTokenizer(max_length=10)
    assert tokenizer.max_length == 10
    assert tokenizer.vocab_size > 0


def test_tokenizer_encode_decode():
    tokenizer = CharacterLevelTokenizer(max_length=20)
    text = "hello world"
    encoded = tokenizer.encode(text)
    assert len(encoded) == 20

    decoded = tokenizer.decode(encoded)
    assert decoded == text


def test_tokenizer_truncation():
    tokenizer = CharacterLevelTokenizer(max_length=5)
    text = "long text"
    encoded = tokenizer.encode(text)
    assert len(encoded) == 5
    assert tokenizer.decode(encoded) == "long "


def test_tokenizer_save_load(tmp_path):
    path = tmp_path / "tokenizer.json"
    tokenizer = CharacterLevelTokenizer(max_length=128)
    tokenizer.save(path)

    new_tokenizer = CharacterLevelTokenizer(max_length=1)  # dummy
    new_tokenizer.load(path)

    assert new_tokenizer.max_length == 128
    assert new_tokenizer.vocab_size == tokenizer.vocab_size
    assert new_tokenizer.encode("test") == tokenizer.encode("test")
