import datetime

from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import CAST
import rsa

class PrivateRingStruct:
    def __init__(self, pu, pr, alg, password):
        self.timestamp = datetime.datetime.now()
        self.pu = pu
        self.pr = pr
        self.alg = alg
        self.password = password

    def __str__(self):
        return "ts: " + str(self.timestamp) + ", PU: " + str(self.pu) + ", PR: " + str(self.pr) + ", alg: " + self.alg

#{userID:janko@gmam. ring:[{puId:.... , }.{}]}

publicRing = {}
privateRing = {}

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
    hp = (digest.finalize())
    hashedPassword=hp[-16:]
    print(hashedPassword)

    cipher=CAST.new(hashedPassword,CAST.MODE_OPENPGP)

    plain=(keys[1]).save_pkcs1('PEM')

    print(plain)
    msg=cipher.encrypt(plain)
    print(msg)

    #Dodavanje u prsten

    if  not privateRing.get(email):
        privateRing[email] = {}

    (privateRing[email])[keys[0]["n"] % (2**64)] = PrivateRingStruct(keys[0], msg, algo, hp)

    print(privateRing[email], str((privateRing[email])[keys[0]["n"] % (2**64)]))


if __name__ == '__main__':
    print('ZP Projekat v1.1')
    poruka = "Iva hrvat"
    generateKeys() #dodati elgamal-dsa, publicRing
