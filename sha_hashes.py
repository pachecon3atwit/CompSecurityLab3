import hashlib
from passlib.hash import sha256_crypt, sha512_crypt

# Passwords to hash
passwords = ["changeme", "123456", "password"]
salt = "somesalt123"  # can be up to 16 characters

# Create output file
with open("sha_hash_results.txt", "w") as f:
    for pw in passwords:
        # SHA-1 (unsalted)
        sha1_hash = hashlib.sha1(pw.encode()).hexdigest()

        sha256_hash = sha256_crypt.using(salt=salt).hash(pw)
        sha512_hash = sha512_crypt.using(salt=salt).hash(pw)

        # Output result
        result = (
            f"Password: {pw}\n"
            f"SHA-1     : {sha1_hash.upper()}\n"
            f"SHA-256   : {sha256_hash}\n"
            f"SHA-512   : {sha512_hash}\n"
            f"{'-'*50}\n"
        )
        print(result)
        f.write(result)
