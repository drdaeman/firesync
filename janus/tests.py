from __future__ import absolute_import, unicode_literals
from django.test import TestCase
from . import auth, hkdf
import binascii
import base64


def H(hex_string, encoding=None):
    value = binascii.a2b_hex(hex_string.replace(" ", ""))
    if encoding is not None:
        value = value.decode(encoding)
    return value


class KnownVectorsTestCase(TestCase):
    """
    Tests implementation against known test vectors.
    """

    def test_hkdf(self):
        """
        Using some RFC5869 test cases, check HKDF implementation
        """
        c1 = hkdf.Hkdf(H("000102030405060708090a0b0c"),
                       H("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
        self.assertEqual(len(c1._prk), 32)
        self.assertEqual(c1._prk, H("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))
        c1 = c1.expand(H("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(len(c1), 42)
        self.assertEqual(c1, H("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))

        c3 = hkdf.Hkdf(b"", H("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
        self.assertEqual(len(c3._prk), 32)
        self.assertEqual(c3._prk, H("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"))
        c3 = c3.expand(b"", 42)
        self.assertEqual(len(c3), 42)
        self.assertEqual(c3, H("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"))

    def test_client_stretch_kdf(self):
        """
        Test implementation against OnePW cient stretch-KDF test vectors
        https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol#test-vectors
        """
        ref_email = H("616e6472c3a94065 78616d706c652e6f 7267", "utf-8")
        ref_password = H("70c3a4737377c3b6 7264", "utf-8")
        ref_authpw_bare = H("247b675ffb4c4631 0bc87e26d712153a be5e1c90ef00a478 4594f97ef54f2375")

        hasher = auth.MozillaOnePWHasher()
        authpw = hasher.encode(ref_password, ref_email)
        # MozillaOnePWHasher produces Django-compatible strings, so we have to format authPW accordingly
        ref_authpw_formatted = "%s$%d$%s$%s" % (hasher.algorithm, hasher.iterations, ref_email,
                                                base64.b64encode(ref_authpw_bare).decode("ascii").strip())
        self.assertEqual(authpw, ref_authpw_formatted, "Invalid authPW")
