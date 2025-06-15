

import os
import hashlib
from typing import Union
from passlib.context import CryptContext







class PasswordHasher:
    """
    PasswordHasher provides utilities for hashing and verifying passwords
    using two strategies:
      - PBKDF2-HMAC-SHA256 (built-in hashlib)
      - Argon2 / Bcrypt / other schemes via passlib

    It applies both a per-installation "pepper" and (for PBKDF2) a per-password "salt".
    """




    # Load or generate a global pepper (16 bytes), stored in an environment variable.
    _PEPPER_ENV = "PASSWORD_HASHER_PEPPER"
    if _PEPPER_ENV in os.environ:
        _pepper = bytes.fromhex(os.environ[_PEPPER_ENV])
    else:
        new_pepper = os.urandom(16)
        os.environ[_PEPPER_ENV] = new_pepper.hex()
        _pepper = new_pepper




    @classmethod
    def _apply_pepper(cls, password: Union[str, bytes]) -> bytes:
        """
        Attach the global pepper to the password bytes.
        """
        pwd_bytes = password.encode() if isinstance(password, str) else password
        return pwd_bytes + cls._pepper




    @classmethod
    def passlib_hash(cls, password: str, scheme: str = "argon2") -> str:
        """
        Hash a password using passlib with the given scheme.

        Args:
            password: The plaintext password to hash.
            scheme:   Passlib-supported scheme (e.g., 'argon2', 'bcrypt').

        Returns:
            A string containing the full hash (including salt & parameters).
        """
        # Create a fresh CryptContext for the requested scheme:
        ctx = CryptContext(schemes=[scheme], deprecated="auto")

        # Combine password + pepper before hashing:
        pwd_peppered = cls._apply_pepper(password)

        # Compute and return the hash:
        return ctx.hash(pwd_peppered)





    @classmethod
    def passlib_verify(cls, password: str, hashed: str, scheme: str = "argon2") -> bool:
        """
        Verify a plaintext password against a passlib hash.

        Args:
            password: The plaintext password to verify.
            hashed:   The stored hashed string.
            scheme:   Scheme used to create the hash.

        Returns:
            True if match, False otherwise.
        """
        ctx = CryptContext(schemes=[scheme], deprecated="auto")
        pwd_peppered = cls._apply_pepper(password)
        return ctx.verify(pwd_peppered, hashed)





    @staticmethod
    def pbkdf2_hmac_hash(
        password: str,
        iterations: int = 100_000
    ) -> str:
        """
        Hash a password using hashlib.pbkdf2_hmac (SHA256).

        A new random salt is generated on each call and prepended to the result.

        Args:
            password:   The plaintext password.
            iterations: Number of PBKDF2 iterations (default: 100,000).

        Returns:
            A hex string in the format: salt_hex$hash_hex
        """
        # Generate a fresh 16-byte salt:
        salt = os.urandom(16)

        # Combine password + global pepper:
        pwd_peppered = password.encode() + PasswordHasher._pepper

        # Derive the key:
        dk = hashlib.pbkdf2_hmac("sha256", pwd_peppered, salt, iterations)

        # Return salt and hash, separated by a dollar sign:
        return f"{salt.hex()}${dk.hex()}"




    @staticmethod
    def pbkdf2_hmac_verify(
        password: str,
        stored: str,
        iterations: int = 100_000
    ) -> bool:
        """
        Verify a plaintext password against a PBKDF2-HMAC stored value.

        Args:
            password:   The plaintext password.
            stored:     The stored salt$hash string.
            iterations: Number of PBKDF2 iterations used initially.

        Returns:
            True if match, False otherwise.
        """
        try:
            salt_hex, hash_hex = stored.split("$", 1)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
        except (ValueError, TypeError):
            return False

        # Combine password + pepper
        pwd_peppered = password.encode() + PasswordHasher._pepper

        # Recompute PBKDF2
        dk = hashlib.pbkdf2_hmac("sha256", pwd_peppered, salt, iterations)
        return hashlib.compare_digest(dk, expected)





