from siglum.canonical import canonical_json, decision_hash


def test_canonical_json_is_key_order_independent():
    a = {"b": 1, "a": [3, 2, 1]}
    b = {"a": [3, 2, 1], "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_canonical_json_is_bytes_and_compact():
    assert canonical_json({"a": 1}) == b'{"a":1}'


def test_decision_hash_is_stable_sha256_hex():
    h1 = decision_hash({"x": 1, "y": 2})
    h2 = decision_hash({"y": 2, "x": 1})
    assert h1 == h2
    assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1)
