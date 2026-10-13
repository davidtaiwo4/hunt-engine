from src.identity import canonicalize_identity


def test_email_style_alias():
    assert canonicalize_identity("amina@example.invalid") == "amina"


def test_domain_backslash_style_alias():
    assert canonicalize_identity("EXAMPLE\\amina") == "amina"


def test_plain_username_unchanged():
    assert canonicalize_identity("amina") == "amina"
