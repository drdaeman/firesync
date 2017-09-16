from django.conf import settings
from django.db import models
from django.utils import timezone
import datetime
import time


class Collection(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    name = models.CharField(max_length=32)
    modified = models.DateTimeField(auto_now=True)

    @property
    def modified_ts(self):
        return int(time.mktime(self.modified.timetuple()))

    class Meta:
        unique_together = [("user", "name")]


class StorageObject(models.Model):
    collection = models.ForeignKey(Collection)
    bsoid = models.CharField(max_length=12)
    modified = models.DateTimeField(auto_now=True)
    expires = models.DateTimeField(null=True, blank=True)
    payload = models.TextField()
    sortindex = models.IntegerField(null=True, blank=True)

    class Meta:
        unique_together = [("collection", "bsoid")]

    @property
    def modified_ts(self):
        return int(time.mktime(self.modified.timetuple()))

    def as_dict(self):
        return {
            "id": self.bsoid,
            "modified": self.modified_ts,
            "sortindex": self.sortindex or 0,
            "payload": self.payload
        }

    def update_from_dict(self, data):
        if "sortindex" in data:
            self.sortindex = data["sortindex"]
        if "payload" in data:
            self.payload = data["payload"]
        if "ttl" in data:
            self.expires = timezone.now() + datetime.timedelta(seconds=data["ttl"])
        return self

    def debug_dump(self, user, password):
        return "<BSO %s: %s %s>" % (self.bsoid, self.modified_ts, self.debug_decode(user, password))

    def debug_decode(self, user, password):
        """
        Debug method to decode encrypted crypto/keys BSO.
        Requires user instance and their plaintext password.

        This code ONLY exists to aid debugging and testing.
        It MUST NOT be called from any production code.
        """
        is_keys = self.bsoid == "keys" and self.collection.name == "crypto"
        if is_keys:
            keys_bso = self
        else:
            keys_bso = Collection.objects.get(user=user, name="crypto").storageobject_set.filter(bsoid="keys").first()
        key_bundle = keys_bso._debug_decode_key_bundle(user, password)
        if is_keys:
            return key_bundle
        else:
            import base64
            enc_key, hmac_key = map(base64.b64decode, key_bundle.get(self.collection.name, key_bundle["default"]))
            return self._debug_decode_bundle(enc_key, hmac_key=hmac_key)

    def _debug_decode_bundle(self, encryption_key, hmac_key):
        import base64, json, hmac, hashlib
        from Crypto.Cipher import AES

        payload = json.loads(self.payload)
        ciphertext_b64 = payload["ciphertext"]

        local_hmac = hmac.HMAC(hmac_key, ciphertext_b64, hashlib.sha256).hexdigest().lower()
        if local_hmac != payload["hmac"].lower():
            raise ValueError("HMAC validation failed for BSO %s", self.bsoid)

        aes = AES.new(encryption_key, AES.MODE_CBC, iv=base64.b64decode(payload["IV"]))
        plaintext = aes.decrypt(base64.b64decode(ciphertext_b64))
        return json.loads(plaintext[0:-ord(plaintext[-1])])

    def _debug_decode_key_bundle(self, user, password):
        import binascii, hashlib
        from janus.auth import MozillaOnePWHasher
        from janus.hkdf import Hkdf
        from janus.views import xor_bytes

        unwrapBKey = MozillaOnePWHasher.expand_key(password, user.email, "unwrapBkey")
        kB = xor_bytes(binascii.a2b_hex(user.keys.wkB), unwrapBKey)

        keys = Hkdf(b"", kB, digest=hashlib.sha256).expand(b"identity.mozilla.com/picl/v1/oldsync", 64)
        encryption_key, hmac_key = keys[0:32], keys[32:64]
        return self._debug_decode_bundle(encryption_key, hmac_key)
