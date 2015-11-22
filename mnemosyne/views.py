from __future__ import unicode_literals, absolute_import

import json
import logging
import datetime
import time

from decorator import decorator
from django.db import transaction
from django.http.response import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404
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


@csrf_exempt
@transaction.atomic
@token_required("x-sync-token")
def storage_collection(request, collection_name):
    user = request.hawk_token.user
    collection = get_object_or_404(Collection, user=user, name=collection_name)

    if request.method == "DELETE":
        collection.delete()
        return response_json({})

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
        return response_json(bso.modified_ts)
    elif request.method == "DELETE":
        collection = get_object_or_404(Collection, user=user, name=collection_name)
        bso = get_object_or_404(StorageObject, collection=collection, bsoid=bsoid)
        bso.delete()
        return response_json({})
    else:
        raise RuntimeError("405 Method Not Allowed")  # FIXME: Return a proper HTTP 405 response here
