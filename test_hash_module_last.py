

#Practical Test Use Case
# Import the PasswordHasher class from the custom hash module
# This module should define a class `PasswordHasher` with a static method `passlib_hash`
from infiniteHasher import PasswordHasher

# Define the plain password you want to hash
password = "jk34df!@DE"






# Hash the password using Argon2 algorithm via passlib
hashed_pass_argon2 = PasswordHasher.passlib_hash(password, "argon2")
print(f"Hashed using Argon2  : {hashed_pass_argon2}")

print("\n")  # Just for spacing in the output







# Hash the password using Bcrypt algorithm via passlib
hashed_pass_bcrypt = PasswordHasher.passlib_hash(password, "bcrypt")
print(f"Hashed using Bcrypt  : {hashed_pass_bcrypt}")

print("\n")  # Extra newline for clean output separation






#Hash the password using pbkdf2_hmac via passlib
hashed_pass_pbkdf2_hmac=PasswordHasher.pbkdf2_hmac_hash(password,100000)
print(f"Hashed using pbkdf2_hmac  : {hashed_pass_pbkdf2_hmac}")

print("\n")  # Extra newline for clean output separation