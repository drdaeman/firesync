from __future__ import unicode_literals, absolute_import

import browserid
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.core.signing import TimestampSigner, BadSignature
from django.http import HttpRequest
from django.http.response import HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.shortcuts import render, get_object_or_404
from django.utils.crypto import constant_time_compare
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import ugettext as _
from django.conf import settings
from decorator import decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from jwkest.jws import JWS
from .auth import MozillaOnePWHasher, get_browserid_key, BrowserIDLocalVerifier
from janus.hkdf import Hkdf
from janus.models import Keys, Device
from .models import User, Token
import six
import json
import time
import binascii
import hashlib
import hmac
import uuid
import logging


logger = logging.getLogger("janus.views")


class HttpResponseNotAuthorized(HttpResponse):
    status_code = 401


def xor_bytes(a, b):
    assert len(a) == len(b), "xor_bytes: lengths differ: %d vs %d" % (len(a), len(b))
    return bytes(bytearray(map(lambda pair: pair[0] ^ pair[1], zip(six.iterbytes(a), six.iterbytes(b)))))


def response_json(data, response_class=HttpResponse, timestamp_header="Timestamp", timestamp_on=(200,)):
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
            logger.error("browserid_required: No BrowserID assertion provided")
            # noinspection PyTypeChecker
            return response_error(
                _("BrowserID authentication required for this request."),
                code=401, errno=109,
                error=_("Authentication required"),
                response_class=HttpResponseNotAuthorized, **error_options)
        elif v.get("status", None) != "okay":
            logger.error("browserid_required: Error verifying BrowserID assertion: %s", v.get("status", None))
            # noinspection PyTypeChecker
            return response_error(
                _("BrowserID authentication failed for this request."),
                code=401, errno=110,
                error=_("Authentication failed"),
                response_class=HttpResponseNotAuthorized, **error_options)
        try:
            request.browserid_user = User.objects.get(email=v["email"])
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            logger.error("browserid_required: Cannot find user for BrowserID assertion with email %s", v["email"])
            # noinspection PyTypeChecker
            return response_error(
                _("Cannot find user matching provided BrowserID authentication. Sorry."),
                code=500, errno=999,
                error=_("Authentication failed"),
                response_class=HttpResponseServerError)
        logger.debug("browserid_required: Got a valid BrowserID assertion for %s", request.browserid_user.email)
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
    user = request.hawk_token.user
    return response_json({
        "devices": [d.as_dict() for d in Device.objects.filter(user=user)]
    })


@csrf_exempt
@require_POST
@hawk_required("sessionToken")
def account_device(request):
    user = request.hawk_token.user
    data = json.loads(request.body.decode("utf-8"))

    device_id = data.get("id", None)
    if device_id is None:
        # Register a new device
        assert "name" in data, "Missing name"  # TODO: Proper validation
        device_id = uuid.uuid4().hex
        device = Device.objects.create(
            id=device_id,
            user=user,
            name=data["name"],
            type=data.get("type", ""),
            push_callback=data.get("pushCallback", ""),
            push_public_key=data.get("pushPublicKey", ""),
            push_auth_key=data.get("pushAuthKey", "")
        )
        logger.info("User %s had registered a new device %s ('%s')", user.username, device.id, device.name)
    else:
        # Update an existing device
        device = Device.objects.select_for_update().get(device_id)
        if "name" in data:
            device.name = data["name"]
        if "type" in data:
            device.type = data["type"]
        if "pushCallback" in data:
            device.push_callback = data["pushCallback"]
        if "pushPublicKey" in data:
            device.push_public_key = data["pushPublicKey"]
        if "pushAuthKey" in data:
            device.push_auth_key = data["pushAuthKey"]
        logger.info("User %s is updating their device %s ('%s')", user.username, device.id, device.name)
        device.save()
    return response_json(device.as_dict())


@hawk_required("sessionToken")
def account_device_notify(request):
    user = request.hawk_token.user
    data = json.loads(request.body.decode("utf-8"))

    assert "to" in data, "Missing to"
    assert "payload" in data, "Missing payload"
    #  TODO: Actually send a push notification
    logger.info("(Not implemented) User %s wanted to ping their devices %s", user.username, repr(data["to"]))

    return response_json({})


@hawk_required("sessionToken")
def account_device_destroy(request):
    user = request.hawk_token.user
    data = json.loads(request.body.decode("utf-8"))
    device_id = data.get("id", None)

    if device_id is not None:
        logger.info("User %s is deleting their device %s", user.username, device_id)
        Device.objects.filter(id=device_id).delete()

    return response_json({})


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
    data = json.loads(request.body.decode("utf-8"))
    assert "publicKey" in data, "Missing publicKey"  # TODO: Proper validation
    assert "duration" in data, "Missing duration"
    now = int(time.time() * 1000)

    key = get_browserid_key()

    jws = JWS(json.dumps({
        "public-key": data["publicKey"],
        "principal": {
            "email": user.email,
        },
        "iss": settings.BROWSERID_ISSUER,
        "iat": now - (10 * 1000),
        "exp": now + data["duration"],
        "fxa-generation": 0,
        "fxa-lastAuthAt": 0,
        "fxa-verifiedEmail": user.email
    }), alg="RS256")   # NOTE: Needs reasonably recent version of pyjwkest
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
    sync_api_uri = '%s://%s%s' % (request.scheme, request.get_host(), "/sync/1.5/")
    return response_json({
        "id": force_text(token.token_id, encoding="ascii"),
        "key": force_text(binascii.a2b_hex(token.expand().hmac_key), encoding="latin-1"),
        "uid": uid,
        "api_endpoint": sync_api_uri,
        "duration": 3600,
        "hashalg": "sha256"
    }, timestamp_header="X-Timestamp", timestamp_on=[200, 401])


@csrf_exempt
def page_signup(request):
    return render(request, "signup.html", {})


@csrf_exempt
def page_signin(request):
    return render(request, "signin.html", {})


@csrf_exempt
@require_POST
def oauth_authorization(request):
    # Here goes the THIRD protocol Mozilla uses for authorization - OAuth.
    # Because I want to save myself from the pains of implementing it, I'm doing the least necessary.
    # I'm using the fact OAuth tokens are opaque, and just throwing in some django.core.signing stuff.
    # That is, the tokens are not something random that's kept in the database, but just signed email
    # addresses with timestamps. The downside, there's no revocation. But, meh, currently I don't care
    # about securing the profile data, given that there isn't anything really private there, yet.
    # Sorry if you feel differently about this.
    data = json.loads(request.body.decode("utf-8"))

    # Currently, ONLY "profile" scope is supported, only with "token" response type.
    # That's what my Firefox seem to request (as usually, totally undocumented,
    # the fxa-oauth-server documentation only mention "code" flow), so that's all that's supported.
    assert data["scope"] == "profile"
    assert data["response_type"] == "token"

    audience = ["%s/oauth/v1" % request.get_host()]
    try:
        verification = BrowserIDLocalVerifier().verify(data["assertion"], audience=audience)
    except browserid.AudienceMismatchError:
        verification = {"status": "error", "_error": "Audience mismatch"}
    if verification["status"] != "okay":
        logger.error("profile_authorization: BrowserID assertion verification failed: %s", repr(verification))
        return response_json({"error": "Not authorized"}, response_class=HttpResponseNotAuthorized)
    logger.debug("profile_authorization: BrowserID assertion verified: %s", repr(verification))

    access_token = TimestampSigner(salt="oauth:token:profile").sign(verification["email"])
    return response_json({
        "access_token": urlsafe_base64_encode(access_token.encode("utf-8")).decode("ascii"),
        "scope": "profile",
        "token_type": "bearer",
        "expires_in": 3600,
        "auth_at": int(time.time()),
    })


@csrf_exempt
def profile_profile(request):
    try:
        token = request.META.get("HTTP_AUTHORIZATION", "").split(None, 1)
        logger.debug("profile: authorization token %s", repr(token))
        if len(token) == 2 and token[0].lower() == "bearer":
            token = urlsafe_base64_decode(token[1])
            logger.debug("profile: decoded token %s", repr(token))
            email = TimestampSigner(salt="oauth:token:profile").unsign(token, max_age=3600)
        else:
            raise KeyError("Unacceptable or missing 'Authorization' header")
    except (KeyError, BadSignature):
        return response_json({"error": "Missing, invalid or expired OAuth token."},
                             response_class=HttpResponseNotAuthorized)

    user = get_object_or_404(User, email=email)
    return response_json({
        "uid": user.username,
        "email": user.email,
        "avatar": HttpRequest.build_absolute_uri(request, static("profile.png")),
    })
