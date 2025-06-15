

# infiniteHasher


A Python utility for secure password hashing and verification, combining a global **pepper** with popular algorithms like **Argon2**, **Bcrypt**, and **PBKDF2-HMAC-SHA256**. Ideal for applications that need flexible, strong password storage.

---





## 📚 Table of Contents

- [🚀 Features](#-features)
- [📦 Installation](#-installation)
- [📖 Usage](#-usage)
- [🔍 API Reference](#-api-reference)
- [⚙️ Security Considerations](#️-security-considerations)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [👨‍💻 Author](#-author)

---





## 🚀 Features

- 🔐 **Global Pepper**: 16-byte per-installation secret automatically generated and stored in an environment variable (`PASSWORD_HASHER_PEPPER`)
- 💪 **Multiple Algorithms**: Support for Argon2, Bcrypt (via [passlib](https://passlib.readthedocs.io/)) and PBKDF2-HMAC-SHA256 (via built-in `hashlib`)
- ✅ **Simple Verification**: One-line verify methods for both passlib and PBKDF2
- 🧱 **Zero External Dependency for PBKDF2**: Uses only Python’s standard library
- ⚙️ **Configurable Iterations**: Especially for PBKDF2, to balance performance and security

---











## 📦 Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/infiniteHasher.git
cd infiniteHasher






# 2. (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate      # On Linux/macOS
venv\Scripts\activate         # On Windows

# 3. Install required dependencies
pip install passlib[argon2]   # For Argon2 support
pip install passlib[bcrypt]   # For Bcrypt support









📖 Usage
python
from infiniteHasher import PasswordHasher





# Your plaintext password
password = "My$tr0ngP@ss!"



# 1. Hash with Argon2 (via passlib)
argon2_hash = PasswordHasher.passlib_hash(password, scheme="argon2")
print("Argon2 hash:", argon2_hash)





# 2. Verify Argon2
assert PasswordHasher.passlib_verify(password, argon2_hash, scheme="argon2")





# 3. Hash with Bcrypt
bcrypt_hash = PasswordHasher.passlib_hash(password, scheme="bcrypt")
print("Bcrypt hash:", bcrypt_hash)







# 4. Verify Bcrypt
assert PasswordHasher.passlib_verify(password, bcrypt_hash, scheme="bcrypt")








# 5. Hash with PBKDF2-HMAC-SHA256
pbkdf2_hash = PasswordHasher.pbkdf2_hmac_hash(password, iterations=100_000)
print("PBKDF2 hash:", pbkdf2_hash)
# Format: <salt_hex>$<derived_key_hex>







# 6. Verify PBKDF2
assert PasswordHasher.pbkdf2_hmac_verify(password, pbkdf2_hash, iterations=100_000)






🔍 API Reference
Class: PasswordHasher
Method	Description
passlib_hash(password, scheme)	Hash using passlib (argon2, bcrypt, etc.)
passlib_verify(password, hash, scheme)	Verify a passlib hash
pbkdf2_hmac_hash(password, iterations)	Hash using PBKDF2-HMAC-SHA256; returns salt$hash
pbkdf2_hmac_verify(password, stored, iterations)	Verify a PBKDF2 hash






⚙️ Security Considerations
🔐 Pepper Protection: The environment variable PASSWORD_HASHER_PEPPER acts as a global secret. Keep it private and out of version control.

🧂 Salt & Iterations: PBKDF2 generates a new random salt every time and supports custom iteration counts.






🧠 Algorithm Choices:

Use Argon2 if available – modern and secure.

Use Bcrypt for legacy compatibility.

Use PBKDF2 for zero-dependency environments.





🤝 Contributing
Fork this repository

Create a feature branch: git checkout -b feature/yourFeature

Commit your changes: git commit -m "Add some feature"

Push to your branch: git push origin feature/yourFeature

Open a Pull Request

Please follow PEP 8 and include tests or docs for new features.




📄 License
This project is licensed under the MIT License. See LICENSE for more details.






👨‍💻 Author
Made with ❤️ by Soma Jahan Madhobilata



---
