import rsa
from Cryptodome.Hash import SHA1
from Cryptodome.Signature import DSS


def msgAuth(msg, privateKey, algo):
    if algo == "RSA":
        return rsa.sign(str(msg).encode('utf-8'), privateKey, 'SHA-1')
    else:
        dsaSign = DSS.new(privateKey, 'fips-186-3')
        hashMsg = SHA1.new(str(msg).encode('utf-8'))
        return dsaSign.sign(hashMsg)


def checkAuth(msg, signature, publicKey, algo):
    if algo == "RSA":
        try:
            rsa.verify(str(msg).encode('utf-8'), signature, publicKey)
            return 1
        except ValueError:
            return 0
    else:
        dsaSign = DSS.new(publicKey, 'fips-186-3')
        hashMsg = SHA1.new(str(msg).encode('utf-8'))
        try:
            dsaSign.verify(hashMsg, signature)
            return 1
        except ValueError:
            return 0
