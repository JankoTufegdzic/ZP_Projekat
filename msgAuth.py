import rsa
from Cryptodome.Hash import SHA1
from Cryptodome.Signature import DSS, pkcs1_15



def msgAuth(msg, privateKey, algo):
    if algo == "RSA":
        # return rsa.sign(str(msg).encode('utf-8'), privateKey, 'SHA-1')
        hashMsg = SHA1.new(str(msg).encode('utf-8'))
        return pkcs1_15.new(privateKey).sign(hashMsg)
    else:
        dsaSign = DSS.new(privateKey, 'fips-186-3')
        hashMsg = SHA1.new(str(msg).encode('utf-8'))
        return dsaSign.sign(hashMsg)


def checkAuth(msg, signature, publicKey, algo):
    hashMsg = SHA1.new(str(msg).encode('utf-8'))
    if algo == "RSA":
        try:
            pkcs1_15.new(publicKey).verify(hashMsg, signature)
            return 1
        except ValueError:
            return 0
    else:
        dsaSign = DSS.new(publicKey, 'fips-186-3')
        try:
            dsaSign.verify(hashMsg, signature)
            return 1
        except ValueError:
            return 0
