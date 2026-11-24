"""Vérification de robustesse et hachage des mots de passe.

- Les listes SecLists sont embarquées dans l'image (aucun appel réseau à
  l'exécution) et chargées une seule fois en mémoire dans un frozenset :
  comparaison exacte en O(1), sans faux positifs.
- Le hachage utilise Argon2id (RFC 9106, recommandé par l'OWASP et l'ANSSI) :
  algorithme lent et coûteux en mémoire, sel aléatoire par mot de passe.
"""

from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"
WORDLISTS = {
    "500 worst passwords": "500-worst-passwords.txt",
    "10K most common passwords": "10k-most-common.txt",
}

MIN_LENGTH = 12
MAX_LENGTH = 128  # borne haute : évite un DoS par hachage de très longues chaînes

# Paramètres par défaut d'argon2-cffi = profil RFC 9106 "low memory"
# (t=3, m=64 MiB, p=4). Sel de 16 octets généré pour chaque hash.
_hasher = PasswordHasher()

# Hash factice : vérifié quand l'utilisateur n'existe pas, pour que la durée
# de réponse soit identique et ne révèle pas quels comptes existent.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalization")


@lru_cache(maxsize=None)
def _load(filename: str) -> frozenset:
    text = (WORDLIST_DIR / filename).read_text(encoding="utf-8",
                                               errors="replace")
    return frozenset(line.strip() for line in text.splitlines()
                     if line.strip())


def find_in_wordlists(password: str):
    """Renvoie le nom de la liste contenant le mot de passe, sinon None."""
    for name, filename in WORDLISTS.items():
        if password in _load(filename):
            return name
    return None


def policy_errors(password: str, username: str = "") -> list:
    """Politique de mot de passe (inspirée NIST SP 800-63B / ANSSI)."""
    errors = []
    if len(password) < MIN_LENGTH:
        errors.append(f"Au moins {MIN_LENGTH} caractères sont requis.")
    if len(password) > MAX_LENGTH:
        errors.append(f"Au plus {MAX_LENGTH} caractères sont autorisés.")
    if username and username.lower() in password.lower():
        errors.append("Le mot de passe ne doit pas contenir l'identifiant.")
    if find_in_wordlists(password):
        errors.append("Ce mot de passe figure dans une liste de mots de "
                      "passe courants.")
    return errors


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash, password: str) -> bool:
    """Vérifie un mot de passe ; temps constant que l'utilisateur existe ou non."""
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) \
            and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True si les paramètres Argon2 ont été renforcés depuis le hachage."""
    return _hasher.check_needs_rehash(stored_hash)
