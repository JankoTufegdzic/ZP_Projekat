import ast
import base64
import zlib

from keyManipulation import *
from msgAuth import *
from msgEncr import *

publicRing = {}
privateRing = {}


def deleteKeys(keyID, email):
    del privateRing[email][keyID]
    del publicRing[keyID]
    return


def saveKeyInPemFormat(key, title, algo):
    if algo == "RSA":
        with open(f'keys/{title}.pem', 'wb') as p:
            p.write(key.save_pkcs1('PEM'))
    elif algo == "DSA":
        with open(f'keys/{title}.pem', 'wb') as p:
            p.write(key.export_key('PEM'))
    elif algo == "ElGamal":
        with open(f'keys/{title}.pem', 'wb') as p:
            toWrite = {}
            toWrite["p"] = key.p
            toWrite["g"] = key.g
            toWrite["y"] = key.y
            toWrite["x"] = key.x
            p.write(bytearray(str(toWrite).encode('utf-8')))


def loadPrivateKeyFromPemFormat(title, email, password):  # izmeniti za elgamal i dsa
    with open(f'keys/{title}.pem', 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        if not privateRing.get(email):
            privateRing[email] = {}

        msg, hp = encryptPrivateKey(password, privateKey)
        publicKey = rsa.PublicKey(privateKey["n"], privateKey["e"])
        (privateRing[email])[privateKey["n"] % (2 ** 64)] = PrivateRingStruct(
            publicKey, msg, "RSA", hp)

        publicRing[publicKey["n"] % (2 ** 64)] = PublicRingStruct(publicKey, "RSA", email)
        return privateKey


def loadPublicKeyFromPemFormat(title, email):  # izmeniti za elgamal i dsa
    with open(f'keys/{title}.pem', 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
        publicRing[publicKey["n"] % (2 ** 64)] = PublicRingStruct(publicKey, "RSA", email)
        return publicKey


def addToRings(email, password, privateKey, publicKey, pubID, algo):
    msg, hp = encryptPrivateKey(password, privateKey, algo)
    if not privateRing.get(email):
        privateRing[email] = {}

    (privateRing[email])[int(pubID) % (2 ** 64)] = PrivateRingStruct(publicKey, msg, algo, hp)

    publicRing[int(pubID) % (2 ** 64)] = PublicRingStruct(publicKey, algo, email)


def generateKeys(name,email,algo,size,password):

    keys = None

    if algo == "RSA":
        keys = generateKeysRSA(size)
        publicKey = keys[0]
        privateKey = keys[1]
        pubID = publicKey["n"]


    elif algo == "DSA":
        keys = generateKeysDSA(size)
        publicKey = keys.public_key()
        privateKey = keys
        pubID = publicKey.y


    elif algo == "ElGamal":
        keys = generateKeysElGamal(size)
        keys = ElGamal.construct((int(keys.p), int(keys.g), int(keys.y), int(keys.x)))
        publicKey = keys.publickey()
        privateKey = keys
        pubID = publicKey.y

    addToRings(email, password, privateKey, publicKey, pubID, algo)
    saveKeyInPemFormat(publicKey, "test", algo)


def sendMessage(email, password, msg, name, publicKeyAuthID=None, publicKeyEncrID=None, encrAlg=None):
    global privateRing, publicRing
    toSend = {}
    toSend["data"] = msg
    toSend["ts"] = datetime.datetime.now()
    toSend["filename"] = name

    if publicKeyAuthID is not None:
        tmp = privateRing[email][publicKeyAuthID]
        privateKeyAuth = decryptPrivateKey(password, tmp.pr, tmp.password, tmp.alg)
        if privateKeyAuth is None:
            return "error"
        authAlg = tmp.alg

        authMsg = {}
        authMsg["data"] = toSend
        authMsg["digest"] = msgAuth(toSend, privateKeyAuth, authAlg)
        authMsg["octets"] = None
        authMsg["authKeyID"] = publicKeyAuthID
        authMsg["tsAuth"] = datetime.datetime.now()
        authMsg["algAuth"] = authAlg
        toSend = authMsg

    toSend = zlib.compress(str(toSend).encode('utf-8'))

    if publicKeyEncrID is not None:
        encrMsg = {}
        print(bytearray(str(toSend).encode("utf-8")))
        kS, encrMsg["data"], encrMsg["iv"] = encryptMsg(toSend, encrAlg)
        # print(kS)
        encrMsg["encrKeyID"] = publicKeyEncrID
        publicKeyEncr = publicRing[publicKeyEncrID].pu
        encrMsg["ks"] = encryptKs(kS, publicKeyEncr, publicRing[publicKeyEncrID].alg)
        encrMsg["algEncr"] = encrAlg
        toSend = encrMsg

    toSend = base64.b64encode(str(toSend).encode('ascii')).decode('ascii')

    with open(f'msgs/{name}.json', "w") as sendmsg:
        sendmsg.write(str(toSend))


def receiveMessage(email, password, name):
    with open(f'msgs/{name}.json') as file:
        toRecv = file.read()

    toRecv = base64.b64decode(toRecv.encode('ascii')).decode("ascii")
    toRecv = ast.literal_eval(toRecv)

    if "ks" in toRecv:
        kS = toRecv["ks"]
        decrKeyID = toRecv["encrKeyID"]
        data = toRecv["data"]
        alg = toRecv["algEncr"]

        tmp = privateRing[email][decrKeyID]
        privateKey = tmp.pr
        hashedPassword = tmp.password
        privateKey = decryptPrivateKey(password, privateKey, hashedPassword, tmp.alg)
        if privateKey is None:
            return "error"

        kS = decryptKs(kS, privateKey, tmp.alg)
        toRecv = decryptMsg(data, alg, kS, toRecv["iv"])

        toRecv = eval(toRecv.decode("utf-8"))

    toRecv = eval(zlib.decompress(toRecv).decode('utf-8'))

    if "digest" in toRecv:
        digest = toRecv["digest"]
        octets = toRecv["octets"]
        authKeyID = toRecv["authKeyID"]
        ts = toRecv["tsAuth"]
        algAuth = toRecv["algAuth"]
        toRecv = toRecv["data"]

        publicKey = publicRing[authKeyID].pu
        print(publicKey)

        if not checkAuth(toRecv, digest, publicKey, algAuth):
            return "error"

    print(toRecv)


if __name__ == '__main__':
    print('ZP Projekat v1.1')
    generateKeys()  # dodati elgamal-dsa, publicRing
    print("done")
    generateKeys()
    # # print(loadPrivateKeyFromPemFormat("test"))
    email = input("Uneti email: ")
    password = input("Uneti sifru: ")
    pr = list(privateRing[email].items())[0][0]
    pu = list(publicRing.items())[1][0]
    print(pr, pu)
    sendMessage(email, password, "radi molim te", "test", pr, pu, "3DES")
    email = input("Uneti email: ")
    password = input("Uneti sifru: ")
    receiveMessage(email, password, "test")
