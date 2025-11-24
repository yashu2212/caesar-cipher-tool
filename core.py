# core.py
import string
import base64
import binascii
import urllib.parse
import os
import hashlib
from typing import List, Tuple, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ALPHABET = string.ascii_lowercase
COMMON_WORDS = ["the","be","to","of","and","a","in","that","have","i","is","it","for","not","on","with","as","you","do","at"]

# ---------------- Caesar ----------------
def caesar_shift(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)

def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_shift(text, -shift)

def caesar_bruteforce(text: str) -> Dict[int,str]:
    return {s: caesar_decrypt(text, s) for s in range(26)}

def common_word_score(text: str) -> int:
    lower = " " + text.lower() + " "
    score = 0
    for w in COMMON_WORDS:
        score += lower.count(" " + w + " ")
    return score

def caesar_auto(text: str) -> Tuple[int, str]:
    """
    Return (best_shift, candidate) by trying all shifts and
    selecting highest common_word_score, tie-breaker english_score.
    """
    brute = caesar_bruteforce(text)
    best = None
    best_key = None
    for s, cand in brute.items():
        cw = common_word_score(cand)
        es = english_score(cand)
        key = (cw, es)
        if best is None or key > best:
            best = key
            best_key = (s, cand)
    if best_key is None:
        return (0, text)
    return best_key

# ---------------- Vigenere ----------------
def vigenere_encrypt(plaintext: str, key: str) -> str:
    if not key:
        return plaintext
    res = []
    ki = 0
    key_up = key.upper()
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            kb = ord(key_up[ki % len(key_up)]) - ord('A')
            res.append(chr((ord(ch) - base + kb) % 26 + base))
            ki += 1
        else:
            res.append(ch)
    return ''.join(res)

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    if not key:
        return ciphertext
    res = []
    ki = 0
    key_up = key.upper()
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            kb = ord(key_up[ki % len(key_up)]) - ord('A')
            res.append(chr((ord(ch) - base - kb) % 26 + base))
            ki += 1
        else:
            res.append(ch)
    return ''.join(res)

# ---------------- Atbash / ROT13 / Base64 ----------------
def atbash(text: str) -> str:
    def m(c):
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            return chr(base + (25 - (ord(c) - base)))
        return c
    return ''.join(m(c) for c in text)

def rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))

def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def b64_decode(text: str) -> str:
    try:
        # tolerant: allow missing padding
        s = text.strip()
        padding = len(s) % 4
        if padding:
            s += "=" * (4 - padding)
        return base64.b64decode(s.encode(), validate=False).decode()
    except Exception:
        return None

# ---------------- hex / binary / url ----------------
def try_hex_decode(text: str) -> str:
    try:
        b = bytes.fromhex(text.strip())
        return b.decode()
    except Exception:
        return None

def try_binary_decode(text: str) -> str:
    s = text.strip().replace(" ", "")
    if s == "":
        return None
    if all(c in "01" for c in s) and len(s) % 8 == 0:
        try:
            out = "".join(chr(int(s[i:i+8],2)) for i in range(0,len(s),8))
            return out
        except Exception:
            return None
    return None

def try_url_decode(text: str) -> str:
    try:
        return urllib.parse.unquote(text)
    except Exception:
        return None

# ---------------- simple english scoring ----------------
def english_score(text: str) -> int:
    score = 0
    low = text.lower()
    for w in COMMON_WORDS:
        score += low.count(w)
    # vowel ratio heuristic
    letters = sum(1 for c in low if c.isalpha())
    vowels = sum(low.count(v) for v in "aeiou")
    if letters > 0:
        vr = vowels / letters
        score += int(vr * 2)
    return score

# ---------------- Hash helpers ----------------
def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()

# ---------------- AES-GCM text/file helpers (password -> key via PBKDF2) ----------------
def _derive_key(password: str, salt: bytes, iterations: int=200000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode())

def aes_encrypt_text(plaintext: str, password: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    payload = salt + nonce + ct
    return base64.urlsafe_b64encode(payload).decode()

def aes_decrypt_text(b64payload: str, password: str) -> str:
    try:
        raw = base64.urlsafe_b64decode(b64payload.encode())
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        plain = aesgcm.decrypt(nonce, ct, None)
        return plain.decode()
    except Exception:
        return None

def aes_encrypt_file(in_path: str, password: str, out_path: str=None) -> str:
    if out_path is None:
        out_path = in_path + ".enc"
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    with open(in_path, "rb") as f:
        data = f.read()
    ct = aesgcm.encrypt(nonce, data, None)
    with open(out_path, "wb") as f:
        f.write(salt + nonce + ct)
    return out_path

def aes_decrypt_file(in_path: str, password: str, out_path: str=None) -> str:
    if out_path is None:
        out_path = in_path + ".dec"
    with open(in_path, "rb") as f:
        raw = f.read()
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ct, None)
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path

# ---------------- Universal decoder (tries many methods & ranks) ----------------
def universal_decode_candidates(text: str, top_n: int=6) -> List[Tuple[str,str,int]]:
    candidates = []
    candidates.append(("raw", text, english_score(text)))
    # rot13
    r = rot13(text)
    candidates.append(("rot13", r, english_score(r)))
    # base64
    bdec = b64_decode(text)
    if bdec is not None:
        candidates.append(("base64", bdec, english_score(bdec)))
    # hex
    hdec = try_hex_decode(text)
    if hdec:
        candidates.append(("hex", hdec, english_score(hdec)))
    # binary
    bnd = try_binary_decode(text)
    if bnd:
        candidates.append(("binary", bnd, english_score(bnd)))
    # url
    urld = try_url_decode(text)
    if urld and urld != text:
        candidates.append(("url", urld, english_score(urld)))
    # atbash
    at = atbash(text)
    candidates.append(("atbash", at, english_score(at)))
    # caesar brute force
    brute = caesar_bruteforce(text)
    for s, cand in brute.items():
        sc = english_score(cand)
        candidates.append((f"caesar({s})", cand, sc))
    # sort and dedupe
    candidates.sort(key=lambda x: x[2], reverse=True)
    seen = set()
    out = []
    for method, cand, sc in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        out.append((method, cand, sc))
        if len(out) >= top_n:
            break
    return out
