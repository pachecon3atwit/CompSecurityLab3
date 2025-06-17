from passlib.hash import apr_md5_crypt

# List of passwords to hash
passwords = ["changeme", "123456", "password"]

fixed_salt = "HX3G1vP1"

def generate_apr1_hash(password, salt=None):
    if salt:
        return apr_md5_crypt.hash(password, salt=salt)
    else:
        return apr_md5_crypt.hash(password)

def main():
    with open("apr1_hash_results.txt", "w") as f:
        for pw in passwords:
            apr1_hash = generate_apr1_hash(pw, fixed_salt)
            result_line = f"Password: {pw}\nAPR1 Hash: {apr1_hash}\n{'-'*40}\n"
            print(result_line)      
            f.write(result_line)    

if __name__ == "__main__":
    main()
