from passlib.hash import pbkdf2_sha1, pbkdf2_sha256

passwords = ["changeme", "123456", "password"]
salt = "ZDzPE45C"
salt_bytes = salt.encode()  # Convert to bytes

with open("pbkdf2_results.txt", "w") as f:
    for pw in passwords:
        hash_sha1 = pbkdf2_sha1.using(salt=salt_bytes).hash(pw)
        hash_sha256 = pbkdf2_sha256.using(salt=salt_bytes).hash(pw)

        short_sha1 = hash_sha1.split('$')[-1][:6]
        short_sha256 = hash_sha256.split('$')[-1][:6]

        result = (
            f"Password: {pw}\n"
            f"Salt: {salt}\n"
            f"PBKDF2-SHA1   : {hash_sha1}\n"
            f"PBKDF2-SHA256 : {hash_sha256}\n"
            f"First 6 chars of SHA1 hash   : {short_sha1}\n"
            f"First 6 chars of SHA256 hash : {short_sha256}\n"
            + "-"*40 + "\n"
        )

        print(result)
        f.write(result)
