from app import passwords


def test_exact_match_no_false_positive():
    # Régression de la faille d'origine : recherche de sous-chaîne
    assert passwords.find_in_wordlists("password") == "500 worst passwords"
    for s in ["a", "b'", "\\n", "zzqqxx"]:  # faux positifs dans l'original
        assert passwords.find_in_wordlists(s) is None


def test_10k_list():
    assert passwords.find_in_wordlists("qwertyuiop") is not None


def test_policy():
    assert passwords.policy_errors("short")
    assert passwords.policy_errors("x" * 200)
    assert passwords.policy_errors("alice-Secure-2026!", "alice")
    assert passwords.policy_errors("Zx9!kq#Lm2@vTr", "bob") == []


def test_hash_is_argon2id_salted_and_verifiable():
    h1 = passwords.hash_password("Zx9!kq#Lm2@vTr")
    h2 = passwords.hash_password("Zx9!kq#Lm2@vTr")
    assert h1.startswith("$argon2id$")
    assert h1 != h2                         # sel aléatoire
    assert "Zx9!kq#Lm2@vTr" not in h1
    assert passwords.verify_password(h1, "Zx9!kq#Lm2@vTr")
    assert not passwords.verify_password(h1, "wrong")
    assert not passwords.verify_password(None, "anything")
    assert not passwords.verify_password("not-a-hash", "x")
