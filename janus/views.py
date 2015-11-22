from __future__ import unicode_literals, absolute_import
from django.http.response import HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.shortcuts import render
from django.utils.crypto import constant_time_compare
from django.utils.translation import ugettext as _
from decorator import decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from jwkest.jws import JWS
from .auth import MozillaOnePWHasher, get_browserid_key
from janus.hkdf import Hkdf
from janus.models import Keys
from .models import User, Token
import six
import json
import time
import binascii
import hashlib
import hmac
import logging


logger = logging.getLogger("janus.views")


class HttpResponseNotAuthorized(HttpResponse):
    status_code = 401


def xor_bytes(a, b):
    assert len(a) == len(b)
    return bytes(bytearray(map(lambda pair: pair[0] ^ pair[1], zip(six.iterbytes(a), six.iterbytes(b)))))


def response_json(data, response_class=HttpResponse, timestamp_header="Timestamp", timestamp_on=[200]):
    logger.debug("JSON response: %s", json.dumps(data))
    r = response_class(json.dumps(data), content_type="application/json")
    if r.status_code in timestamp_on and timestamp_header is not None:
        r[timestamp_header] = int(time.time())
    return r


def response_error(message, code=400, errno=999, error=_("Bad Request"), response_class=HttpResponseBadRequest,
                   timestamp_header=None):
    logger.error("Responding with HTTP %s error %s: %s", code, errno, message)
    return response_json({
        "code": code,
        "errno": errno,
        "error": error,
        "message": message
    }, response_class=response_class, timestamp_header=timestamp_header, timestamp_on=[code])


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


def browserid_required(**error_options):
    # TODO: Add extra validations, in particular fxa-generation and application
    # Currently we just check that we get back an assertion we trust. And use email from there.
    # But we don't do any further check. Given that we only run Sync that's probably OK.
    @decorator
    def _browserid_required(f, request, *args, **kwargs):
        v = request.browserid_verification
        if v is None:
            # noinspection PyTypeChecker
            return response_error(
                _("BrowserID authentication required for this request."),
                code=401, errno=109,
                error=_("Authentication required"),
                response_class=HttpResponseNotAuthorized, **error_options)
        elif v.get("status", None) != "okay":
            # noinspection PyTypeChecker
            return response_error(
                _("BrowserID authentication failed for this request."),
                code=401, errno=110,
                error=_("Authentication failed"),
                response_class=HttpResponseNotAuthorized, **error_options)
        try:
            request.browserid_user = User.objects.get(email=v["email"])
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            # noinspection PyTypeChecker
            return response_error(
                _("Cannot find user matching provided BrowserID authentication. Sorry."),
                code=500, errno=999,
                error=_("Authentication failed"),
                response_class=HttpResponseServerError)
        return f(request, *args, **kwargs)
    return _browserid_required


@csrf_exempt
def account_create(request):
    # This is intentional
    return response_error(_("Account creation is not supported."))


@csrf_exempt
def account_status(request):
    uid = request.POST.get("uid", request.GET.get("uid", "")).strip()
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
    logger.info("User %s was successfully authenticated", user.email)
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
    logger.info("User %s had fetched their keys", user.email)
    return response_json({
        "bundle": bundle
    })


@csrf_exempt
@require_POST
@hawk_required("sessionToken")
def certificate_sign(request):
    user = request.hawk_token.user
    data = json.loads(request.body)
    assert "publicKey" in data, "Missing publicKey"  # TODO: Proper validation
    assert "duration" in data, "Missing duration"
    now = int(time.time() * 1000)

    key = get_browserid_key()

    jws = JWS(json.dumps({
        "public-key": data["publicKey"],
        "principal": {
            "email": user.email,
        },
        "iss": "localhost:8000",
        "iat": now - (10 * 1000),
        "exp": now + data["duration"],
        "fxa-generation": 0,
        "fxa-lastAuthAt": 0,
        "fxa-verifiedEmail": user.email
    }), alg=b"RS256")  # Beware: if we'd use u"RS256" here, things will go wrong and we'll have {"alg":null}
    cert = jws.sign_compact([key])

    return response_json({"cert": cert})


@csrf_exempt
@require_POST
@hawk_required("sessionToken")
def session_destroy(request):
    request.hawk_token.delete()
    return response_json({})


@csrf_exempt
@browserid_required(timestamp_header="X-Timestamp")
def token_sync(request):
    uid = request.browserid_user.username
    token = Token.issue("x-sync-token", request.browserid_user)
    logger.debug("Issued sync token: " + repr(token))
    # Mozilla services use tokenlib here and encode everything in token ID.
    # We don't want two different middlewares handling this mess, so assuming
    # the fact we're running both Janus and Mnemosyne in the same system,
    # sharing Janus Tokens, we just generate one.
    # The tricky (and possibly fragile) part is that "key" must be passed RAW,
    # not base64- or hex-encoded, or the validation will fail.
    return response_json({
        "id": token.token_id,
        "key": binascii.a2b_hex(token.expand().hmac_key).decode("latin-1"),
        "uid": uid,
        "api_endpoint": "https://localhost:8000/sync/1.5/",
        "duration": 3600,
        "hashalg": "sha256"
    }, timestamp_header="X-Timestamp", timestamp_on=[200, 401])


@csrf_exempt
def page_signup(request):
    return render(request, "signin.html", {})


@csrf_exempt
def page_signin(request):
    return render(request, "signin.html", {})
