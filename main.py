from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import CAST
import rsa




def generateKeysRSA(size):
    return rsa.newkeys(size)
def generateKeysDSA(size):
    pass

def deleteKeysRSA():
    pass
def deleteKeysDSA():
    pass

def saveKeyInPemFormat(key,title):
    with open(f'keys/{title}.pem', 'wb') as p:
        p.write(key.save_pkcs1('PEM'))

def loadPublicKeyFromPemFormat(title):
    with open(f'keys/{title}.pem', 'rb') as p:
        return rsa.PublicKey.load_pkcs1(p.read())

def loadPrivateKeyFromPemFormat(title):
    with open(f'keys/{title}.pem', 'rb') as p:
        return rsa.PrivateKey.load_pkcs1(p.read())

def generateKeys():
    name=input("Unesite ime")
    email=input("Unesite email")
    algo=input("Unesite algoritam ")
    size=int(input("Unesite velicini"))
    keys=None
    if algo=="RSA":
        keys=generateKeysRSA(size)
    else :
        keys=generateKeysDSA(size)
    password = input("Unesite lozinku")
    digest = hashes.Hash(hashes.SHA1())
    ba=bytearray(password.encode('utf-8'))
    digest.update(ba)
    hashedPassword=(digest.finalize())[-16:]
    print(hashedPassword)

    cipher=CAST.new(hashedPassword,CAST.MODE_OPENPGP)

    plain=(keys[1]).save_pkcs1('PEM')

    print(plain)
    msg=cipher.encrypt(plain)
    print(msg)



    #Dodavanje u prsten

if __name__ == '__main__':
    print('ZP Projekat v1.1')
    poruka = "Iva hrvat"
    generateKeys()

