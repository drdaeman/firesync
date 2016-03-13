from __future__ import unicode_literals, absolute_import

import json
import logging
import datetime
import time

from decorator import decorator
from django.db import transaction
from django.http.response import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.utils.timezone import UTC
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from .models import Collection, StorageObject


logger = logging.getLogger("mnemosyne.views")


def response_json(data, response_class=HttpResponse, timestamp_header="Timestamp", timestamp_on=[200]):
    logger.debug("JSON response: %s", json.dumps(data))
    r = response_class(json.dumps(data), content_type="application/json")
    if r.status_code in timestamp_on and timestamp_header is not None:
        r[timestamp_header] = int(time.time())
    return r


def token_required(token_type):
    @decorator
    def _token_required(f, request, *args, **kwargs):
        hawk_token = getattr(request, "hawk_token", None)
        logger.debug("Got HAWK token: %s", repr(hawk_token))
        if hawk_token is not None and hawk_token.token_type == token_type:
            return f(request, *args, **kwargs)
        else:
            # FIXME: This isn't a correct response. Should be 401.
            return HttpResponseForbidden("Failed to validate HAWK token")
    return _token_required


@token_required("x-sync-token")
def info_collections(request):
    user = request.hawk_token.user
    return response_json({
        collection.name: collection.modified_ts
        for collection in Collection.objects.filter(user=user)
    })


@token_required("x-sync-token")
def info_quota(request):
    return response_json([0, None])


@token_required("x-sync-token")
def info_collection_usage(request):
    user = request.hawk_token.user
    return response_json({
        collection.name: 0
        for collection in Collection.objects.filter(user=user)
    })


def _put_bso(collection, bsoid, data):
    try:
        bso = StorageObject.objects.get(collection=collection, bsoid=bsoid)
        bso.update_from_dict(data)
        bso.save()
    except StorageObject.DoesNotExist:
        expires = None if "ttl" not in data else timezone.now() + datetime.timedelta(seconds=data["ttl"])
        bso = StorageObject.objects.create(collection=collection, bsoid=bsoid,
                                           payload=data.get("payload", None),
                                           sortindex=data.get("sortindex", None),
                                           expires=expires)
    return bso


@csrf_exempt
@transaction.atomic
@token_required("x-sync-token")
def storage_collection(request, collection_name):
    user = request.hawk_token.user

    if request.method == "POST" or (request.method == "DELETE" and "ids" in request.GET):
        collection, _created = Collection.objects.get_or_create(user=user, name=collection_name)
        bsoids = set()

        if request.method == "POST":
            data = json.loads(request.body)
            bso = None
            for item in data:
                bso = _put_bso(collection, item["id"], item)
                bsoids.add(bso.bsoid)
            return response_json({
                "modified": bso.modified_ts if bso is not None else None,
                "success": list(bsoids),
                "failed": {}   # TODO: We really never fail?
            })
        elif request.method == "DELETE" and "ids" in request.GET:
            for bsoid in request.GET.getlist("ids"):
                try:
                    bso = StorageObject.objects.get(collection=collection, bsoid=bsoid)
                    bsoids.add(bso.bsoid)
                    bso.delete()
                except StorageObject.DoesNotExist:
                    pass
                if bsoids:
                    # We had deleted something - touch the collection's last modification date
                    collection.modified = timezone.now()
                    collection.save()
            return response_json({
                "modified": collection.modified_ts
            })
        else:
            # Should never happen, unless parent "if" and this "if" are not in sync.
            raise RuntimeError("Something went wrong. The code hadn't covered this %s request" % request.method)
    else:
        collection = get_object_or_404(Collection, user=user, name=collection_name)

    if request.method == "DELETE":
        collection.delete()
        return response_json({})
    elif request.method == "GET":
        bso_qs = collection.storageobject_set.all()

        sort_by = request.GET.get("sort", None)
        if sort_by == "newest":
            bso_qs = bso_qs.order_by("-modified")
        elif sort_by == "oldest":
            bso_qs = bso_qs.order_by("modified")
        else:  # "index" or not specified
            bso_qs = bso_qs.order_by("-sortindex")

        if "newer" in request.GET:
            newer_than = datetime.datetime.fromtimestamp(int(request.GET["newer"]), UTC())
            bso_qs = bso_qs.filter(modified__gt=newer_than)

        # TODO: Implement limit and offset support for collections

        if "full" not in request.GET:
            result = bso_qs.values_list("bsoid", flat=True)
        else:
            result = [bso.as_dict() for bso in bso_qs]
        return response_json(result)

    raise RuntimeError("Sorry, not implemented yet") # TODO: FIXME: Implement this


@csrf_exempt
@transaction.atomic
@token_required("x-sync-token")
def storage_object(request, collection_name, bsoid):
    user = request.hawk_token.user

    if request.method == "GET":
        collection = get_object_or_404(Collection, user=user, name=collection_name)
        bso = get_object_or_404(StorageObject, collection=collection, bsoid=bsoid)
        return response_json(bso.as_dict())
    elif request.method == "PUT":
        # TODO: This request may include the X-If-Unmodified-Since header to avoid overwriting the data
        data = json.loads(request.body)
        collection, _created = Collection.objects.get_or_create(user=user, name=collection_name)
        bso = _put_bso(collection, bsoid, data)
        return response_json(bso.modified_ts)
    elif request.method == "DELETE":
        collection = get_object_or_404(Collection, user=user, name=collection_name)
        bso = get_object_or_404(StorageObject, collection=collection, bsoid=bsoid)
        bso.delete()
        return response_json({})
    else:
        raise RuntimeError("405 Method Not Allowed")  # FIXME: Return a proper HTTP 405 response here
