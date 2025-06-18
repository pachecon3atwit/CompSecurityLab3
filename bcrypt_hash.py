import hashlib
from passlib.hash import des_crypt, md5_crypt, bcrypt, sun_md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt

# Word to hash
string = "hello"

# Salt values (DES needs 2 chars, Bcrypt needs 22)
salt = "ZDzPE45C"
salt2 = "1111111111111111111111"

md5_val = hashlib.md5(string.encode()).hexdigest()
sha1_val = hashlib.sha1(string.encode()).hexdigest()
sha256_val = hashlib.sha256(string.encode()).hexdigest()
sha512_val = hashlib.sha512(string.encode()).hexdigest()

des_val = des_crypt.using(salt=salt[:2]).hash(string)
md5_unix = md5_crypt.using(salt=salt).hash(string)
bcrypt_val = bcrypt.using(salt=salt2[:22], rounds=6).hash(string)
sun_md5_val = sun_md5_crypt.using(salt=salt).hash(string)
sha1_crypt_val = sha1_crypt.using(salt=salt).hash(string)
sha256_crypt_val = sha256_crypt.using(salt=salt).hash(string)
sha512_crypt_val = sha512_crypt.using(salt=salt).hash(string)

print("General Hashes (first 6 hex chars):")
print(f"MD5    : {md5_val[:6]} ({len(md5_val)} hex chars)")
print(f"SHA1   : {sha1_val[:6]} ({len(sha1_val)} hex chars)")
print(f"SHA256 : {sha256_val[:6]} ({len(sha256_val)} hex chars)")
print(f"SHA512 : {sha512_val[:6]} ({len(sha512_val)} hex chars)")

print("\nUNIX-Style Salted Hashes (full output):")
print(f"DES      : {des_val}")
print(f"MD5      : {md5_unix}")
print(f"Bcrypt   : {bcrypt_val}")
print(f"Sun MD5  : {sun_md5_val}")
print(f"SHA1     : {sha1_crypt_val}")
print(f"SHA256   : {sha256_crypt_val}")
print(f"SHA512   : {sha512_crypt_val}")
