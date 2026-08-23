from app.auth.security import generate_api_key, hash_api_key, hash_password, verify_password


def test_hash_password_produces_different_hash_than_plaintext():
    hashed = hash_password("mypassword123")
    assert hashed != "mypassword123"


def test_verify_password_correct():
    hashed = hash_password("mypassword123")
    assert verify_password("mypassword123", hashed) is True


def test_verify_password_incorrect():
    hashed = hash_password("mypassword123")
    assert verify_password("wrongpassword", hashed) is False


def test_hash_password_is_salted_differently_each_time():
    h1 = hash_password("samepassword")
    h2 = hash_password("samepassword")
    assert h1 != h2
    # but both verify correctly
    assert verify_password("samepassword", h1)
    assert verify_password("samepassword", h2)


def test_generate_api_key_is_url_safe_and_high_entropy():
    key1 = generate_api_key()
    key2 = generate_api_key()
    assert key1 != key2
    assert len(key1) > 32
    # URL-safe base64 alphabet only
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert set(key1) <= allowed


def test_hash_api_key_is_deterministic():
    key = "some-api-key-value"
    assert hash_api_key(key) == hash_api_key(key)


def test_hash_api_key_different_keys_different_hashes():
    assert hash_api_key("key-one") != hash_api_key("key-two")


def test_hash_api_key_is_sha256_hex():
    result = hash_api_key("test")
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)
