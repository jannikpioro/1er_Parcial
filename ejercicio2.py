# Ejercicio 2
# Sign a document

# Import the required libraries
import hashlib
import Crypto.Util.number as CUN
import Crypto.Random

# Function to compute the SHA-256 hash of a PDF file and return it as an integer
def hash_pdf(file_path):
    sha256 = hashlib.sha256()  # Initialize SHA-256 hash object
    with open(file_path, "rb") as f:  # Open the file in binary mode
        while chunk := f.read(4096):  # Read the file in 4KB chunks
            sha256.update(chunk)  # Update the hash with each chunk
    return int.from_bytes(sha256.digest(), byteorder='big')  # Return the final hash as an integer

# For "e" we use number 4 of Fernat
e = 65537

# We calculate the public keys of Alice
pA = CUN.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)	
qA = CUN.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
print("\n", "RSA Public Key Alice: ", nA)

# We calculate the public key of the AC
pAC = CUN.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)	
qAC = CUN.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nAC = pAC * qAC
print("\n", "RSA Public Key the AC: ", nAC)

# We calculate the private key of Alice
phiA = (pA - 1) * (qA - 1)
dA = CUN.inverse(e, phiA)
print("\n", "Private Key Alice: ", dA)

# We calculate the private key of the AC
phiAC = (pAC - 1) * (qAC - 1)
dAC = CUN.inverse(e, phiAC)
print("\n", "Private Key the AC: ", dAC)

# Compute the hash of NDA.pdf
hM = hash_pdf(r"C:\Users\Janni\OneDrive\Dokumente\Studium\Auslandssemester\Klassen\Cybersecurity\1er parcial\Parcial\NDA.pdf") 
print("\n", "Hash of the hM: ", hex(hM))

# We sign the hash of the message using the private key of Alice and we send it to "la Autoridad Certificadora (AC)"
sA = pow(hM, dA, nA)
print("\n", "Signature of Alice: ", sA)

# AC verifies the signature using the public key of Alice
hM1 = pow(sA, e, nA)
print("\n", "Hash of hM:1: ", hex(hM1))

# AC signs the hash of the decrypted NDA using the private key of the AC and sends it to Bob
sAC = pow(hM1, dAC, nAC)
print("\n", "Signature of the AC: ", sAC)

# Bob verifies the signature using the public key of the AC
hM2 = pow(sAC, e, nAC)
print("\n", "Hash of hM2: ", hex(hM2))

# Verify the signature
print("\n", "Signature is valid: ", hM == hM2)


