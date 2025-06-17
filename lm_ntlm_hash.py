import hashlib
from Crypto.Cipher import DES
from Crypto.Hash import MD4

# Pad password to 14 bytes (LM only)
def pad_lm_password(password):
    return password.upper().ljust(14, '\0')

# Create 56-bit DES key from 7-byte string
def create_des_key(key_7bytes):
    key = []
    key.append(ord(key_7bytes[0]) >> 1)
    key.append(((ord(key_7bytes[0]) & 0x01) << 6) | (ord(key_7bytes[1]) >> 2))
    key.append(((ord(key_7bytes[1]) & 0x03) << 5) | (ord(key_7bytes[2]) >> 3))
    key.append(((ord(key_7bytes[2]) & 0x07) << 4) | (ord(key_7bytes[3]) >> 4))
    key.append(((ord(key_7bytes[3]) & 0x0F) << 3) | (ord(key_7bytes[4]) >> 5))
    key.append(((ord(key_7bytes[4]) & 0x1F) << 2) | (ord(key_7bytes[5]) >> 6))
    key.append(((ord(key_7bytes[5]) & 0x3F) << 1) | (ord(key_7bytes[6]) >> 7))
    key.append(ord(key_7bytes[6]) & 0x7F)

    for i in range(len(key)):
        b = key[i]
        b = (b << 1)
        key[i] = b & 0xFE  # clear LSB (parity bit)
    return bytes(key)

# Calculate LM Hash
def lm_hash(password):
    pw14 = pad_lm_password(password)
    part1 = create_des_key(pw14[0:7])
    part2 = create_des_key(pw14[7:14])
    msg = b"KGS!@#$%"  # fixed string

    des1 = DES.new(part1, DES.MODE_ECB)
    des2 = DES.new(part2, DES.MODE_ECB)

    hash1 = des1.encrypt(msg)
    hash2 = des2.encrypt(msg)
    return (hash1 + hash2).hex().upper()

# Calculate NTLM Hash
def ntlm_hash(password):
    pw_utf16 = password.encode('utf-16le')
    md4_hasher = MD4.new()
    md4_hasher.update(pw_utf16)
    return md4_hasher.hexdigest().upper()

# Main runner
if __name__ == "__main__":
    passwords = ["Napier", "Foxtrot"]
    output_lines = []

    for pw in passwords:
        lm = lm_hash(pw)
        ntlm = ntlm_hash(pw)
        output_lines.append(f"Password: {pw}")
        output_lines.append(f"LM Hash   : {lm}")
        output_lines.append(f"NTLM Hash : {ntlm}")
        output_lines.append("-" * 40)

    # Print to screen
    for line in output_lines:
        print(line)

    # Save to file
    with open("hash_results.txt", "w") as f:
        for line in output_lines:
            f.write(line + "\n")
