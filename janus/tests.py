from __future__ import absolute_import, unicode_literals
from django.test import TestCase
from . import auth, hkdf, models
import binascii
import base64
import mohawk
import json


def H(hex_string, encoding=None):
    value = binascii.a2b_hex(hex_string.replace(" ", ""))
    if encoding is not None:
        value = value.decode(encoding)
    return value


def b64decode(data):
    """
    Helper function to decode base64.

    Accepts both standard and "URL-safe" encoded strings
    and recovers from missing padding (trailing "=" chars).
    """
    data = data.replace("-", "+").replace("_", "/")
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += "=" * missing_padding
    return base64.b64decode(data)


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


class AccountTest(TestCase):
    TEST_USER_UID = "test_user"
    TEST_USER_EMAIL = "nobody@example.org"
    TEST_USER_PASSWORD = "verysecret"

    def setUp(self):
        models.User.objects.create_user(self.TEST_USER_UID, self.TEST_USER_EMAIL, self.TEST_USER_PASSWORD)

    def test_signin_page(self):
        """
        Tests that sign-in HTML page renders.
        """
        response = self.client.get("/signin")
        self.assertEqual(response.status_code, 200, "Failed to fetch sign-in page")

    def test_login(self):
        """
        Tests the login sequence.
        """
        # Generate "authPW" value from the plaintext password
        auth_pw = auth.MozillaOnePWHasher().encode(self.TEST_USER_PASSWORD, self.TEST_USER_EMAIL)
        auth_pw_prefix = "{0}$1000${1}$".format(auth.MozillaOnePWHasher.algorithm, self.TEST_USER_EMAIL)
        self.assertTrue(auth_pw.startswith(auth_pw_prefix), "MozillaOnePWHasher returned something weird")
        auth_pw = auth_pw[len(auth_pw_prefix):]

        # Try to log in
        credentials = json.dumps({
            "email": self.TEST_USER_EMAIL,
            "authPW": auth_pw
        })
        response = self.client.post("/v1/account/login?keys=true", data=credentials,
                                    content_type="application/json")
        self.assertEqual(response.status_code, 200, "Invalid HTTP status code while logging in")

        # Validate the response. We should've successfully logged in.
        login_data = response.json()
        for key in ["uid", "sessionToken", "keyFetchToken", "verified"]:
            self.assertIn(key, login_data, "Missing response key {}".format(key))
        self.assertEqual(login_data["uid"], self.TEST_USER_UID, "Logged in as unexpected user")
        self.assertTrue(login_data["verified"], "User not verified")

        # Our certificate for signing
        public_key = "BLAH"  # FIXME
        key_data = json.dumps({
            "publicKey": public_key,
            "duration": 3600
        })

        # Send the request to sign our certificate. It's HAWK-authenticated with sessionToken.
        token = hkdf.Hkdf(b"", H(login_data["sessionToken"])).expand(b"identity.mozilla.com/picl/v1/sessionToken", 64)
        token = token[0:32], token[32:64]
        hawk_auth = mohawk.Sender({
            "id": binascii.b2a_hex(token[0]),
            "key": token[1],
            "algorithm": "sha256"
        }, "http://testserver/v1/certificate/sign", "POST", content=key_data, content_type="application/json")
        response = self.client.post("/v1/certificate/sign", data=key_data, content_type="application/json",
                                    HTTP_AUTHORIZATION=hawk_auth.request_header)
        self.assertEqual(response.status_code, 200, "Invalid HTTP status code while signing certificate")

        # Validate the certificate signing response.
        cert_data = response.json()
        self.assertIn("cert", cert_data, "No certificate data in response")
        cert_data = cert_data["cert"]
        self.assertTrue(cert_data != "", "Empty certificate data")

        # Parse and validate the returned signature
        jws = list(map(b64decode, cert_data.split(".")))
        self.assertEqual(len(jws), 3, "Returned JWS looks invalid")
        jws[0] = json.loads(jws[0])
        self.assertEqual(jws[0]["alg"], "RS256", "JWS is not RSA-signed. Either we had implemented ECDSA"
                                                 " or something went wrong.")
        jws[1] = json.loads(jws[1])
        self.assertEqual(jws[1]["fxa-verifiedEmail"], self.TEST_USER_EMAIL, "JWS: Mismatching fxa-verifiedEmail")
        self.assertEqual(jws[1]["principal"]["email"], self.TEST_USER_EMAIL, "JWS: Mismatching principal.email")
        self.assertEqual(jws[1]["public-key"], public_key, "JWS: Mismatching public-key")
