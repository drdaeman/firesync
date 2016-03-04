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
            "sortindex": self.sortindex,
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