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
message = "14159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038196442881097566593344612847564823378678316527120190914564856692346034861045432664821339360726024914127372458700660631558817488152092096282540917153643678925903600113305305488204665213841469519415116094330572703657595919530921861173819326117931051185480744623799627495673518857527248912279381830119491298336733624406566430860213949463952247371907021798609437027705392171762931767523846748184676694051320005681271452635608277857713427577896091736371787214684409012249534301465495853710507922796892589235420199561121290219608640344181598136297747713099605187072113499999837297804995105973173281609631859502445945534690830264252230825334468503526193118817101000313783875288658753320838142061717766914730359825349042875546873115956286388235378759375195778180532171226806613001927876611195909216420198938095257201065485863278865936153381827968230301952"
print("\n", "Message: ", message)

# Generate the hash of the message
hM = hashlib.sha256(message.encode('utf-8')).hexdigest()
print("\n", "Hash of the message (hM): ", hM)

# Divide the message into parts of 128 characters
parts = [message[i:i+128] for i in range(0, len(message), 128)]
print("\n", "Parts of the message: ", parts)

# Alice encrypts each part with Bob's public key
encrypted_parts = [pow(int(part), e, nB) for part in parts]
print("\n", "Encrypted parts: ", encrypted_parts)	

# Bob decrypts each part with his private key and reconstructs the original message
# Added zfill(128) to the decrypted parts to ensure that they are 128 characters long (leading zeros were removed during the encryption decryption process)
# except last part which may be less than 128 characters
decrypted_parts = [str(pow(encrypted_part, dB, nB)).zfill(128) if i < len(encrypted_parts) - 1 else str(pow(encrypted_part, dB, nB)) for i, encrypted_part in enumerate(encrypted_parts)]
print("\n", "Decrypted parts: ", decrypted_parts)

# Reconstruct the original message
reconstructed_message = ''.join(decrypted_parts)
print("\n", "Reconstructed Message: ", reconstructed_message)

# Bob generates the hash of the reconstructed message
hM_prime = hashlib.sha256(reconstructed_message.encode('utf-8')).hexdigest()
print("\n", "Hash of the reconstructed message (hM'): ", hM_prime)

# Verify the authenticity of the message
print("\n", "The message is authentic: ", hM == hM_prime)