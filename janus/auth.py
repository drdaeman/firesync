from __future__ import unicode_literals
from django.conf import settings
from django.contrib.auth.hashers import BasePasswordHasher, mask_hash
from django.utils.crypto import pbkdf2, constant_time_compare
from django.utils.translation import ugettext_lazy as _
from janus.hkdf import Hkdf
from janus.models import Token
import mohawk
import mohawk.exc
import browserid
import hashlib
import base64
import binascii
import os
import os.path
import collections
import logging


logger = logging.getLogger("janus.auth")


class MozillaOnePWHasher(BasePasswordHasher):
    algorithm = "mozilla_onepw"
    iterations = 1000
    digest = hashlib.sha256

    @classmethod
    def expand_key(cls, password, qs_salt, hkdf_salt, iterations=None):
        if not iterations:
            iterations = cls.iterations
        full_salt = "identity.mozilla.com/picl/v1/quickStretch:{0}".format(qs_salt)
        p_hash = pbkdf2(password, full_salt, iterations, dklen=32, digest=cls.digest)
        return Hkdf(b"", p_hash).expand("identity.mozilla.com/picl/v1/{0}".format(hkdf_salt).encode("ascii"), 32)

    def encode(self, password, salt, iterations=None):
        assert password is not None
        assert salt and "$" not in salt
        if not iterations:
            iterations = self.iterations
        p_hash = self.expand_key(password, salt, "authPW", iterations=iterations)
        p_hash = base64.b64encode(p_hash).decode("ascii").strip()
        return "%s$%d$%s$%s" % (self.algorithm, iterations, salt, p_hash)

    def verify(self, password, encoded):
        algorithm, iterations, salt, p_hash = encoded.split("$", 3)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt, int(iterations))
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        algorithm, iterations, salt, p_hash = encoded.split("$", 3)
        assert algorithm == self.algorithm
        return collections.OrderedDict([
            (_('algorithm'), self.algorithm),
            (_('iterations'), iterations),
            (_('salt'), mask_hash(salt, show=2)),
            (_('hash'), mask_hash(p_hash)),
        ])


def _lookup_token(sender_id):
    try:
        token = Token.objects.get(token_id=sender_id)
        # I'm sure desktop Firefox (54.0a2) wants raw binary strings and produces
        # invalid HAWK signatures otherwise.
        #
        # This doesn't seem to work with Firefox for Android, though (cause unknown)
        # and contradicts tokenlib source where it seems that keys should be base64-encoded.
        #
        # https://github.com/mozilla-services/tokenserver/blob/c62b8519/tokenserver/views.py#L294
        # https://github.com/mozilla-services/tokenlib/blob/e270a029/tokenlib/__init__.py#L158
        # https://github.com/mozilla-services/tokenlib/blob/e270a029/tokenlib/utils.py#L69
        #
        # NOTE: (added at a later time) this could be actually a misunderstanding on my side,
        #       caused by reuse of tokens for sync auth.
        #
        #       Those (x-sync-token) must be printable for Android to work, while
        #       non-sync ones (sessionToken and keyFetch) are expected to be raw.
        #
        #       Check views.token_sync for more info.
        return {
            "id": token.token_id,
            "key": binascii.a2b_hex(token.expand().hmac_key),
            "algorithm": "sha256",
            "x-token-object": token
        }
    except Token.DoesNotExist:
        logger.error("No such token: %s", sender_id)
        raise mohawk.exc.CredentialsLookupError("Unknown or invalid token")

def _lookup_token_b64(sender_id):
    token = _lookup_token(sender_id)
    token["key"] = base64.b64encode(token["key"])
    return token


class HawkAuthenticationMiddleware(object):
    @staticmethod
    def process_request(request):
        uri = "(unknown)"
        try:
            if "HTTP_AUTHORIZATION" not in request.META:
                raise KeyError("No HTTP_AUTHORIZATION")  # Fail before the breakpoint
            authorization = request.META["HTTP_AUTHORIZATION"]
            if not authorization.lower().startswith("hawk "):
                raise KeyError("Not a HAWK authorization")
            # We have to do this manually, because HttpRequest.build_absolute_uri() and
            # HttpRequest.get_full_path() would return us a forcibly-escaped pathes
            # (they all unconditionally pass data through uri_to_iri), and we need
            # everything exactly as we got from the network here.
            uri = '%s://%s%s%s' % (
                request.scheme, request.get_host(), request.path,
                ("?" + request.META.get("QUERY_STRING", "")) if request.META.get("QUERY_STRING", "") else ""
            )
            if settings.DEBUG and uri.startswith("http://"):
                # Hax since stunnel doesn't add any headers for us.
                uri = "https://" + uri[7:]
            content_type = request.META.get("HTTP_CONTENT_TYPE", None)
            if content_type is None:
                if request.body == b"":
                    content = None
                else:
                    content = request.body
                    content_type = "application/json"
            else:
                content = request.body
            lookup = _lookup_token
            if "android" in request.META.get("HTTP_USER_AGENT", "").lower() and "sync" in request.path:
                # XXX: This is a hack. See views.token_sync for details.
                lookup = _lookup_token_b64
            receiver = mohawk.Receiver(
                lookup,
                authorization,
                uri,
                request.method,
                content=content,
                content_type=content_type,
                accept_untrusted_content=True)
            request.hawk_auth_receiver = receiver
            request.hawk_token = receiver.resource.credentials["x-token-object"]
            request.user = request.hawk_token.user
        except (mohawk.exc.HawkFail, KeyError) as e:
            if not isinstance(e, KeyError):
                logger.error("HAWK request failed for %s %s: %s", request.method, uri, repr(e))
            request.hawk_auth_receiver = None
            request.hawk_token = None
            request.user = None


class BrowserIDAuthenticationMiddleware(object):
    @staticmethod
    def process_request(request):
        try:
            if "HTTP_AUTHORIZATION" not in request.META:
                raise KeyError("No HTTP_AUTHORIZATION")  # Fail before the breakpoint
            authorization = request.META["HTTP_AUTHORIZATION"]
            if not authorization.lower().startswith("browserid "):
                raise KeyError("Not a BrowserID authorization")

            authorization = authorization.split(" ", 1)
            assert authorization[0].lower() == "browserid"
            authorization = authorization[1]
            verifier = BrowserIDLocalVerifier()
            request.browserid_verification = verifier.verify(authorization)
        except (KeyError, browserid.Error) as e:
            if not isinstance(e, KeyError):
                logger.exception("Failed to verify BrowserID assertion: %s", repr(e))
            request.browserid_verification = None


class BrowserIDLocalTrustSupport(object):
    def is_trusted_issuer(self, hostname, issuer, trusted_secondaries):
        print("is_trusted_issuer: %s, %s, %r" % (hostname, issuer, trusted_secondaries))
        return issuer in trusted_secondaries

    def get_key(self, issuer):
        if issuer == settings.BROWSERID_ISSUER:
            key = get_browserid_key()
            key = {_k: getattr(key, _k) for _k in list(set(key.public_members) & set(key.longs))}
            if "algorithm" not in key:
                key["algorithm"] = "RS"
            return key
        else:
            raise NotImplementedError("Can't get key for %s" % issuer)


class BrowserIDLocalVerifier(browserid.LocalVerifier):
    def __init__(self, warning=True):
        super(BrowserIDLocalVerifier, self).__init__(
            audiences=["https://%s" % settings.BROWSERID_ISSUER],
            trusted_secondaries=[settings.BROWSERID_ISSUER],
            supportdocs=BrowserIDLocalTrustSupport(),
            warning=warning
        )


_RSAKEY = None
def get_browserid_key():
    global _RSAKEY
    from Crypto.PublicKey import RSA
    from jwkest.jwk import RSAKey
    if _RSAKEY is None:
        try:
            if os.path.exists(settings.BROWSERID_KEY_FILE):
                with open(settings.BROWSERID_KEY_FILE, "rb") as f:
                    _RSAKEY = RSA.importKey(f.read())
                logger.info("Loaded RSA keypair from %s", settings.BROWSERID_KEY_FILE)
        except BaseException as e:
            logger.exception("Error loading existing RSA keypair: %s", repr(e))
            _RSAKEY = None
        if _RSAKEY is None:
            _RSAKEY = RSA.generate(1024)  # TODO: FIXME: Totally insecure!
            logger.warning("Generated RSA keypair. The key is WEAK and INSECURE, use for testing only.")
            with open(settings.BROWSERID_KEY_FILE, "wb") as f:
                f.write(_RSAKEY.exportKey("PEM"))
            logger.info("Saved RSA keypair to %s", settings.BROWSERID_KEY_FILE)
    return RSAKey(kid=b"rsa1", key=_RSAKEY)  # It's important that kid is a byte string, not unicode
