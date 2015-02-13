from __future__ import unicode_literals
import binascii
from django.conf import settings

from django.contrib.auth.hashers import BasePasswordHasher, mask_hash
from django.utils.crypto import pbkdf2, constant_time_compare
from django.utils.translation import ugettext_lazy as _
from django.utils.datastructures import SortedDict
import mohawk, mohawk.exc
import hashlib
import base64
from janus.hkdf import Hkdf
from janus.models import Token


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
        return SortedDict([
            (_('algorithm'), self.algorithm),
            (_('iterations'), iterations),
            (_('salt'), mask_hash(salt, show=2)),
            (_('hash'), mask_hash(p_hash)),
        ])


def _lookup_token(sender_id):
    try:
        token = Token.objects.get(token_id=sender_id)
        #print("found token: " + repr(token))
        return {
            "id": token.token_id,
            "key": binascii.a2b_hex(token.expand().hmac_key),
            "algorithm": "sha256",
            "x-token-object": token
        }
    except Token.DoesNotExist:
        raise mohawk.exc.CredentialsLookupError("Unknown or invalid token")


class HawkAuthenticationMiddleware(object):
    @staticmethod
    def process_request(request):
        try:
            if not "HTTP_AUTHORIZATION" in request.META:
                raise KeyError("No HTTP_AUTHORIZATION")  # Fail before the breakpoint
            uri = request.build_absolute_uri()
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
            receiver = mohawk.Receiver(
                _lookup_token,
                request.META["HTTP_AUTHORIZATION"],
                uri,
                request.method,
                content=content,
                content_type=content_type,
                accept_untrusted_content=True)
            request.hawk_auth_receiver = receiver
            request.hawk_token = receiver.resource.credentials["x-token-object"]
            request.user = request.hawk_token.user
        except (mohawk.exc.HawkFail, KeyError) as e:
            # print("fail: " + repr(e))
            request.hawk_auth_receiver = None
            request.hawk_token = None
            request.user = None
