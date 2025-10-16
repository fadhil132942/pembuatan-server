import hashlib
import secrets
import base64
import hmac
import os
ALG = 'sha256'         # algoritma HMAC yang digunakan
ITERATIONS = 200_000   # jumlah iterasi PBKDF2 (semakin besar, semakin aman)
SALT_BYTES = 16        # panjang salt dalam bytes
DKLEN = 32             # panjang hash yang dihasilkan
def generate_salt(n_bytes: int = SALT_BYTES) -> bytes:
    """Buat salt acak aman kriptografis."""
    return secrets.token_bytes(n_bytes)

def hash_password(password: str, salt: bytes, iterations: int = ITERATIONS,
                  algorithm: str = ALG, dklen: int = DKLEN) -> bytes:
    """
    Hash password menggunakan PBKDF2-HMAC.
    """
    password_bytes = password.encode('utf-8')
    dk = hashlib.pbkdf2_hmac(algorithm, password_bytes, salt, iterations, dklen=dklen)
    return dk
def b64(b: bytes) -> str:
    """Encode bytes ke base64."""
    return base64.b64encode(b).decode('ascii')

def unb64(s: str) -> bytes:
    """Decode base64 ke bytes."""
    return base64.b64decode(s.encode('ascii'))

def format_stored(iterations: int, salt: bytes, dk: bytes) -> str:
    """Format: iterations$salt_base64$hash_base64"""
    return f"{iterations}${b64(salt)}${b64(dk)}"

def parse_stored(stored: str):
    """Pisahkan data tersimpan jadi (iterations, salt_bytes, hash_bytes)."""
    parts = stored.split('$')
    if len(parts) != 3:
        raise ValueError("Format hash invalid")
    iterations = int(parts[0])
    salt = unb64(parts[1])
    dk = unb64(parts[2])
    return iterations, salt, dk
def verify_password(password_attempt: str, stored: str) -> bool:
    """
    Verifikasi password:
    - Ambil salt & hash dari data tersimpan
    - Hash ulang password input
    - Bandingkan dengan hash tersimpan
    """
    iterations, salt, dk_stored = parse_stored(stored)
    dk_attempt = hash_password(password_attempt, salt, iterations)
    return hmac.compare_digest(dk_attempt, dk_stored)
if __name__ == "__main__":
    # 1) Registrasi (hash password baru)
    user_password = "rahasiaKu123!"
    salt = generate_salt()
    dk = hash_password(user_password, salt)
    stored_value = format_stored(ITERATIONS, salt, dk)
    print("Disimpan di database:")
    print(stored_value)
    print()

# 2) Coba login (password benar)
attempt_good = "rahasiaKu123!"
print("Password benar?", verify_password(attempt_good, stored_value))

# 3) Coba login (password salah)
attempt_bad = "passwordSalah"
print("Password salah?", verify_password(attempt_bad, stored_value))
