from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature
import hashlib
import binascii


def h2hash(f):
    if f == hashlib.sha256:
        return hashes.SHA256()
    elif f == hashlib.sha1:
        return hashes.SHA1()
    raise ValueError("Unsupported hash: %s" % repr(f))


class Key(object):
    KEY_MODULE = None
    _BACKEND = default_backend()

    @classmethod
    def from_pem_data(cls, data=None, filename=None):
        if data is None:
            with open(filename, "r") as f:
                data = f.read()
        self = cls.__new__(cls)
        self.keyobj = serialization.load_pem_private_key(data, backend=self._BACKEND)
        return self

    def to_pem_data(self):
        return self.keyobj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("ascii")

    def verify(self, signed_data, signature):
        raise NotImplementedError

    def sign(self, data):
        raise NotImplementedError


class RSKey(Key):
    KEY_MODULE = None
    DIGESTSIZE = None
    HASHNAME = None
    HASHMOD = None

    def __init__(self, data):
        if not ("e" in data and "n" in data):
            raise ValueError("RSA key mising 'e' and/or 'n'")
        if "d" in data:
            p, q = rsa.rsa_recover_prime_factors(data["n"], data["e"], data["d"])
            self.keyobj = rsa.RSAPrivateNumbers(p, q, data["d"],
                                                rsa.rsa_crt_dmp1(data["d"], p),
                                                rsa.rsa_crt_dmq1(data["d"], q),
                                                rsa.rsa_crt_iqmp(p, q)).private_key(self._BACKEND)
        else:
            self.keyobj = rsa.RSAPublicNumbers(data["e"], data["n"]).public_key(self._BACKEND)

    def verify(self, signed_data, signature):
        # pss = padding.PSS(mgf=padding.MGF1(h2hash(self.HASHMOD)), salt_length=padding.PSS.MAX_LENGTH)
        pss = padding.PKCS1v15()
        public_key = self.keyobj if isinstance(self.keyobj, rsa.RSAPublicKey) else self.keyobj.public_key()
        verifier = public_key.verifier(signature, pss, h2hash(self.HASHMOD))
        verifier.update(signed_data)
        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False

    def sign(self, data):
        # pss = padding.PSS(mgf=padding.MGF1(h2hash(self.HASHMOD)), salt_length=padding.PSS.MAX_LENGTH)
        pss = padding.PKCS1v15()
        signer = self.keyobj.signer(pss, h2hash(self.HASHMOD))
        signer.update(data)
        return signer.finalize()


class DSKey(Key):
    KEY_MODULE = None
    BITLENGTH = None
    HASHMOD = None

    def __init__(self, data):
        if "x" in data:
            # Because I'm a lazy fuck.
            # And I doubt there's much reason to possess and actually use a DSA private key in 2016.
            raise RuntimeError("DSA private keys are not supported.")
        if not ("y" in data and "g" in data and "p" in data and "q" in data):
            raise ValueError("DSA key missing one or more parameters. Want 'y', 'g', 'p' and 'q'.")
        pn = dsa.DSAParameterNumbers(int(data["p"], 16), int(data["q"], 16), int(data["g"], 16))
        self.keyobj = dsa.DSAPublicNumbers(int(data["y"], 16), pn).public_key(self._BACKEND)

    def verify(self, signed_data, signature):
        # Restore any leading zero bytes that might have been stripped.
        signature = binascii.hexlify(signature)
        hexlength = self.BITLENGTH // 4
        signature = signature.rjust(hexlength * 2, b"0")
        if len(signature) != hexlength * 2:
            return False
        # Split the signature into "r" and "s" components.
        r = int(signature[:hexlength], 16)
        s = int(signature[hexlength:], 16)
        der_signature = utils.encode_dss_signature(r, s)

        verifier = self.keyobj.verifier(der_signature, h2hash(self.HASHMOD))
        verifier.update(signed_data)
        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False
