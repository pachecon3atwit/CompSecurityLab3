from passlib.hash import phpass

# List of passwords
passwords = ["changeme", "123456", "password"]

# Salt (8 characters). You can modify this or generate randomly.
salt = "ZDzPE45C"

rounds = 7

with open("phpass_results.txt", "w") as f:
    for pw in passwords:
        hash_value = phpass.using(salt=salt, rounds=rounds).hash(pw)

        # Extract the first 5 characters for result column
        prefix = hash_value[:5]

        result = f"Password: {pw}\nSalt: {salt}\nHash: {hash_value}\nPrefix: {prefix}\n{'-'*40}\n"
        print(result)
        f.write(result)
