from __future__ import unicode_literals, absolute_import
from django.http.response import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.utils.crypto import constant_time_compare
from django.utils.translation import ugettext as _
from decorator import decorator
from django.views.decorators.csrf import csrf_exempt
from .auth import MozillaOnePWHasher
from janus.hkdf import Hkdf
from janus.models import Keys
from .models import User, Token
import json
import time
import binascii
import hashlib
import hmac


class HttpResponseNotAuthorized(HttpResponse):
    status_code = 401


def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(map(lambda pair: pair[0] ^ pair[1], zip(a, b)))


def response_json(data, response_class=HttpResponse):
    r = response_class(json.dumps(data), content_type="application/json")
    if r.status_code == 200:
        r["Timestamp"] = int(time.time())
    return r


def response_error(message, code=400, errno=999, error=_("Bad Request"), response_class=HttpResponseBadRequest):
    return response_json({
        "code": code,
        "errno": errno,
        "error": error,
        "message": message
    }, response_class=response_class)


def hawk_required(token_type):
    @decorator
    def _hawk_required(f, request, *args, **kwargs):
        if request.hawk_token is None:
            # noinspection PyTypeChecker
            return response_error(
                _("Hawk authentication required for this request."),
                code=401, errno=109,
                error=_("Authentication required"),
                response_class=HttpResponseNotAuthorized)
        elif request.hawk_token.token_type != token_type:
            # noinspection PyTypeChecker
            return response_error(
                _("Invalid token for this requests."),
                code=401, errno=110,
                error=_("Authentication required"),
                response_class=HttpResponseNotAuthorized)
        return f(request, *args, **kwargs)
    return _hawk_required


@csrf_exempt
def account_create(request):
    # This is intentional
    return response_error(_("Account creation is not supported."))


@csrf_exempt
def account_status(request):
    uid = request.REQUEST.get("uid", "").strip()
    if uid == "":
        return response_error(_("Missing or empty UID"), errno=108)
    return response_json({"exists": User.objects.filter(username=uid).count() > 0})


@csrf_exempt
def account_login(request):
    request_body = json.loads(request.body.decode("utf-8"))

    try:
        user = User.objects.get(email=request_body.get("email", ""))
    except User.DoesNotExist:
        return response_error(_("Account with given email address does not exists"), errno=102)

    if "authPW" in request_body:
        # Django keeps passwords in "<algorithm>$<iterations>$<salt>$<hash>" format, so adapt authPW to those
        password = "{0}$1000${1}${2}".format(MozillaOnePWHasher.algorithm, user.email, request_body["authPW"])
    elif "plaintextPW" in request_body:
        # Because I'm not going to do crypto in JS
        password = MozillaOnePWHasher().encode(request_body["plaintextPW"], user.email)
    else:
        return response_error(_("Password's missing"), errno=103)

    if not constant_time_compare(user.password, password):
        return response_error(_("Incorrect password"), errno=103)

    session_token = Token.issue("sessionToken", user)
    key_fetch_token = Token.issue("keyFetchToken", user)

    r = {
        "uid": user.username,
        "sessionToken": session_token.token_seed,
        "keyFetchToken": key_fetch_token.token_seed,
        "verified": True,
        "authAt": int(time.time()),
    }
    if "plaintextPW" in request_body:
        # Dumb client, insecure (but they gave us their password anyway, already)
        r["unwrapBKey"] = binascii.b2a_hex(MozillaOnePWHasher.expand_key(request_body["plaintextPW"],
                                                                         user.email, "unwrapBkey")).decode("ascii")
    return response_json(r)


@hawk_required("sessionToken")
def account_devices(request):
    return response_json({
        "devices": [{
            "id": "4c352927-cd4f-4a4a-a03d-7d1893d950b8",
            "type": "computer",
            "name": "Test device"
        }]
    })


@hawk_required("keyFetchToken")
def account_keys(request):
    token = request.hawk_token
    user = request.hawk_token.user
    request.hawk_token.delete()

    user_keys = Keys.get_for_user(user)
    payload = binascii.a2b_hex(user_keys.kA + user_keys.wkB)
    assert len(payload) == 2 * 32

    key_material = Hkdf(b"", binascii.a2b_hex(token.expand().request_key), digest=hashlib.sha256)\
        .expand(b"identity.mozilla.com/picl/v1/account/keys", 3 * 32)
    hmac_key = key_material[0:32]
    xor_key = key_material[32:96]

    ciphertext = xor_bytes(payload, xor_key)
    mac = hmac.HMAC(hmac_key, ciphertext, digestmod=hashlib.sha256).digest()
    bundle = binascii.b2a_hex(ciphertext + mac).decode("ascii")
    return response_json({
        "bundle": bundle
    })


@csrf_exempt
def page_signup(request):
    return render(request, "signin.html", {})


@csrf_exempt
def page_signin(request):
    return render(request, "signin.html", {})
