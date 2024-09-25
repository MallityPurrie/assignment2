import bip32utils
import os
import hashlib

# Generate a random 256-bit (32-byte) seed
seed = os.urandom(32)

# Generate the BIP-32 root key from the seed
root_key = bip32utils.BIP32Key.fromEntropy(seed)

# Display parent key information
print("Parent Private Key (WIF):", root_key.WalletImportFormat())
print("Parent Public Key:", root_key.PublicKey().hex())

# Derive child key at index 0 (can change index as required)
child_key = root_key.ChildKey(0)

# Display child key information
print("\nChild Private Key (WIF):", child_key.WalletImportFormat())
print("Child Public Key:", child_key.PublicKey().hex())

# Check that public child key can be derived from parent public key
parent_public_key = bip32utils.BIP32Key.fromExtendedKey(root_key.ExtendedKey(public=True))
child_public_key_from_parent = parent_public_key.ChildKey(0)
print("\nChild Public Key from Parent Public Key:", child_public_key_from_parent.PublicKey().hex())

# Verify that the public child key from the parent public key matches the one from the private key
if child_public_key_from_parent.PublicKey() == child_key.PublicKey():
    print("\nSuccess: Public child key matches the one derived from the private child key.")
else:
    print("\nError: Public child key does not match.")
