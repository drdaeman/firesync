import collections
import binascii
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password
from django.db import models
from django.utils.crypto import get_random_string
from janus.hkdf import Hkdf
import logging


ExpandedToken = collections.namedtuple("ExpandedToken", "token_id hmac_key request_key")
logger = logging.getLogger("janus.models")


def random_token_hex(octets=32):
    return get_random_string(length=octets * 2, allowed_chars="0123456789abcdef")


class User(AbstractUser):
    def set_password(self, raw_password):
        self.password = make_password(raw_password, salt=self.email)


class Token(models.Model):
    token_id = models.CharField(max_length=64, primary_key=True)
    token_seed = models.CharField(max_length=64, unique=True)
    token_type = models.CharField(max_length=16)
    user = models.ForeignKey(User)

    @staticmethod
    def _expand(seed, token_type):
        expanded = Hkdf(b"", binascii.a2b_hex(seed))
        if token_type == "keyFetchToken":
            expanded = expanded.expand("identity.mozilla.com/picl/v1/{0}".format(token_type).encode("ascii"), 3 * 32)
            return ExpandedToken(binascii.b2a_hex(expanded[0:32]),
                                 binascii.b2a_hex(expanded[32:64]),
                                 binascii.b2a_hex(expanded[64:96]))
        else:
            expanded = expanded.expand("identity.mozilla.com/picl/v1/{0}".format(token_type).encode("ascii"), 2 * 32)
            return ExpandedToken(binascii.b2a_hex(expanded[0:32]), binascii.b2a_hex(expanded[32:64]), None)

    def expand(self):
        return self._expand(self.token_seed, self.token_type)

    @classmethod
    def issue(cls, token_type, user):
        seed = random_token_hex(32)
        t = cls._expand(seed, token_type)
        logger.debug("Issuing token of type %s for user %s: %s -> %s", token_type, user.email, seed, repr(t))
        return cls.objects.create(token_type=token_type, user=user, token_seed=seed, token_id=t.token_id)

    def __repr__(self):
        return "<Token type={0.token_type} user={0.user!r} id={0.token_id} e={1!r}>".format(self, self.expand())


class Keys(models.Model):
    user = models.OneToOneField(User, primary_key=True)
    kA = models.CharField(max_length=64)
    wkB = models.CharField(max_length=64)

    @classmethod
    def get_for_user(cls, user):
        try:
            return cls.objects.get(user=user)
        except cls.DoesNotExist:
            return cls.objects.create(user=user, kA=random_token_hex(32), wkB=random_token_hex(32))
