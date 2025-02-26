# Ejercicio 1

import Crypto
import Crypto.Util.number as CUN
import Crypto.Random
import hashlib

# We use the number 4 of Fernat for "e"
e = 65537

# We calculate the public keys of Alice
pA = CUN.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qA = CUN.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
print("\n", "RSA Public Key Alice: ", nA)

# We calculate the private key of Alice
phiA = (pA - 1) * (qA - 1)
dA = CUN.inverse(e, phiA)
print("\n", "Private Key Alice: ", dA)

# We calculate the public keys of Bob
pB = CUN.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qB = CUN.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nB = pB * qB
print("\n", "RSA Public Key Bob: ", nB)

# We calculate the private key of Bob
phiB = (pB - 1) * (qB - 1)
dB = CUN.inverse(e, phiB)
print("\n", "Private Key Bob: ", dB)

# We use the first  1050 decimal places of pi as the message
message = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec, vulputate eget, arcu. In enim justo, rhoncus ut, imperdiet a, venenatis vitae, justo. Nullam dictum felis eu pede mollis pretium. Integer tincidunt. Cras dapibus. Vivamus elementum semper nisi. Aenean vulputate eleifend tellus. Aenean leo ligula, porttitor eu, consequat vitae, eleifend ac, enim. Aliquam lorem ante, dapibus in, viverra quis, feugiat a, tellus. Phasellus viverra nulla ut metus varius laoreet. Quisque rutrum. Aenean imperdiet. Etiam ultricies nisi vel augue. Curabitur ullamcorper ultricies nisi. Nam eget dui. Etiam rhoncus. Maecenas tempus, tellus eget condimentum rhoncus, sem quam semper libero, sit amet adipiscing sem neque sed ipsum. Nam quam nunc, blandit vel, luctus pulvinar, hendre"
print("\n", "Message: ", message)

# Divide the message into parts of 128 characters
parts = [message[i:i+128] for i in range(0, len(message), 128)]
print("\n", "Parts of the message: ", parts)

# Convert the parts of the message to integers
parts_int = [int.from_bytes((part.encode('utf-8')), byteorder='big') for part in parts]
print("\n", "Parts of the message as integers: ", parts_int)

# Alice encrypts each part with Bob's public key
encrypted_parts = [pow((part), e, nB) for part in parts_int] # here because we convert parts in integer
print("\n", "Encrypted parts: ", encrypted_parts)	

# Bob decrypts each part with his private key
decrypted_parts = [(pow(encrypted_part, dB, nB)) for encrypted_part in encrypted_parts]
print("\n", "Decrypted parts: ", decrypted_parts)

# Translate integers back to bytes and then to strings
decrypted_parts_bytes = [part.to_bytes((part.bit_length() + 7) // 8, byteorder='big') for part in decrypted_parts]
print("\n", "Decrypted parts as bytes: ", decrypted_parts_bytes)

# Bob reconstructs the original message from bytes
reconstructed_message = ''.join([bytes_part.decode('utf-8') for bytes_part in decrypted_parts_bytes])
print("\n", "Reconstructed Message: ", reconstructed_message)

# We generate the hash of the reconstructed message and original message
hM = hashlib.sha256(message.encode('utf-8')).hexdigest()
hM_prime = hashlib.sha256(reconstructed_message.encode('utf-8')).hexdigest()

# Verify the authenticity of the message
print("\n", "The message is authentic: ", hM == hM_prime)