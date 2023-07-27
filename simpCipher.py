def pad_plaintext(plaintext, block_size):
    padding_length = block_size - len(plaintext) % block_size
    return plaintext + bytes([padding_length] * padding_length)

def unpad_plaintext(padded_plaintext):
    padding_length = padded_plaintext[-1]
    return padded_plaintext[:-padding_length]

def simp_encrypt(plaintext, key):
    block_size = len(key)
    padded_plaintext = pad_plaintext(plaintext, block_size)
    ciphertext = b""
    
    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i:i + block_size]
        xored_block = bytes(a ^ b for a, b in zip(block, key))
        modified_block = bytes((x + 42) % 256 for x in xored_block)  # A simple modification (can be replaced with other operations)
        encrypted_block = bytes(a ^ b for a, b in zip(modified_block, key))
        ciphertext += encrypted_block
        
    return ciphertext

def simp_decrypt(ciphertext, key):
    block_size = len(key)
    padded_plaintext = b""
    
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        xored_block = bytes(a ^ b for a, b in zip(block, key))
        modified_block = bytes((x - 42) % 256 for x in xored_block)  # Reverse of the encryption modification
        decrypted_block = bytes(a ^ b for a, b in zip(modified_block, key))
        padded_plaintext += decrypted_block
        
    plaintext = unpad_plaintext(padded_plaintext)
    return plaintext

if __name__ == "__main__":
    mode = input("Enter 'encrypt' or 'decrypt': ").lower()
    
    if mode == 'encrypt':
        plaintext = input("Enter the plaintext: ").encode()
        key = input("Enter the key (in bytes, e.g., \\x01\\x02\\x03): ").encode()

        # Encryption
        ciphertext = simp_encrypt(plaintext, key)
        print("Ciphertext:", ciphertext.hex())

    elif mode == 'decrypt':
        ciphertext_hex = input("Enter the ciphertext (in hexadecimal): ")
        key = input("Enter the key (in bytes, e.g., \\x01\\x02\\x03): ").encode()
        ciphertext = bytes.fromhex(ciphertext_hex)

        # Decryption
        decrypted_text = simp_decrypt(ciphertext, key)
        print("Decrypted text:", decrypted_text.decode())

    else:
        print("Invalid mode. Please enter 'encrypt' or 'decrypt'.")