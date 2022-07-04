from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from .models import *

import jwt
from datetime import datetime, timedelta
import json
import os.path as path
import time

startTime = time.time()
rootDir = path.abspath(path.join(__file__, "../../../certs"))
JWT_PRIVATE_KEY = open(path.join(rootDir, "private.key")).read()
JWT_PUBLIC_KEY = open(path.join(rootDir, "public.pem")).read()

COOKIE_TIME_TO_LIVE_DAYS = 7
JWT_TOKEN_COOKIE_NAME = 'jwt_token'
JWT_PERMISSIONS_COOKIE_NAME = 'jwt_permissions'


def liveliness(req):
    return JsonResponse({"message": "OK", "time": int(time.time()), "uptime": time.time() - startTime}, status=200, safe=False)


def auth(req):
    if req.body and req.method == "POST":
        try:
            obj = json.loads(req.body)
            username = obj['username']
            password = obj['password']
            user = authenticate(req, username=username, password=password)
        except:
            return JsonResponse({"status": "400", "message": "Bad request body"}, status=400, safe=False)

        if user is not None:
            token = issueJWT(user.id)

            response = JsonResponse(
                {"status": "200", "message": "User authenticated", 'token': token}, status=200, safe=False)
            cookie_expiry = datetime.now() + timedelta(days=COOKIE_TIME_TO_LIVE_DAYS)
            response.set_cookie(JWT_TOKEN_COOKIE_NAME,
                                token, expires=cookie_expiry)
            return response
        else:
            return JsonResponse({"status": "403", "message": "User not authenticated"}, status=403, safe=False)

    else:
        return JsonResponse({"status": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def register(req):
    if req.body and req.method == "POST":
        try:
            obj = json.loads(req.body)
            username = obj['username']
            password = obj['password']
        except:
            return JsonResponse({"status": "400", "message": "Bad request"}, status=400, safe=False)

        try:
            if User.objects.get(username=username):
                return JsonResponse({"status": "409", "message": "Username already in use"}, status=400, safe=False)
        except:
            pass

        user = User.objects.create_user(username=username, password=password)
        user.save()

        responseData = {
            "userID": user.id,
            "username": user.username
        }

        return JsonResponse({"status": "200", "message": "User registered", "data": responseData}, status=200, safe=False)
    else:
        return JsonResponse({"status": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def update_profile(req):
    if req.body and req.method == "POST":
        if req.COOKIES.get(JWT_TOKEN_COOKIE_NAME):
            token = validateJWT(req.COOKIES.get(JWT_TOKEN_COOKIE_NAME))
            if token:
                # try to update password
                try:
                    obj = json.loads(req.body)
                    password = obj['password']
                    user = User.objects.get(id=token['userID'])
                    if user:
                        user.set_password(password)
                        user.save()
                    else:
                        return JsonResponse({"status": "404", "message": "User not found"}, status=404, safe=False)
                except:
                    pass

                return JsonResponse({"status": "200"}, status=200, safe=False)
        return JsonResponse({"status": "400", "message": "Invalid or missing "+JWT_TOKEN_COOKIE_NAME+" cookie"}, status=400, safe=False)
    else:
        return JsonResponse({"status": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


# admin management
def reset_user_password(req):
    if req.body and req.method == "POST":
        if req.COOKIES.get(JWT_TOKEN_COOKIE_NAME):
            # user needs to be admin to reset other user passwords
            if req.COOKIES.get(JWT_PERMISSIONS_COOKIE_NAME):
                auth_token = validateJWT(req.COOKIES.get(JWT_TOKEN_COOKIE_NAME))  # nopep8
                perm_token = validateJWT(req.COOKIES.get(JWT_PERMISSIONS_COOKIE_NAME))  # nopep8
                # validate cookies
                if (auth_token):
                    if (perm_token):
                        if (userIsAdmin(perm_token, auth_token)):
                            obj = json.loads(req.body)
                            user = User.objects.get(id=obj['jwt_id'])

                            if user:
                                user.set_password(obj['new_password'])
                                user.save()
                            else:
                                return JsonResponse({"status": "404", "message": "User not found"}, status=404, safe=False)

                            return JsonResponse({"status": "200", "message": "User password has been reset"}, status=200, safe=False)
                        else:
                            return JsonResponse({"status": "403", "message": "Permission token problem"}, status=403, safe=False)
        return JsonResponse({"status": "400", "message": "Bad request cookies"}, status=400, safe=False)
    else:
        return JsonResponse({"status": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def getAllUsers(req):
    if req.method == "GET":
        if req.COOKIES.get(JWT_TOKEN_COOKIE_NAME):
            if req.COOKIES.get(JWT_PERMISSIONS_COOKIE_NAME):
                auth_token = validateJWT(req.COOKIES.get(JWT_TOKEN_COOKIE_NAME))  # nopep8
                perm_token = validateJWT(req.COOKIES.get(JWT_PERMISSIONS_COOKIE_NAME))  # nopep8
                # validate cookies
                if (auth_token):
                    if (perm_token):
                        if (userIsAdmin(perm_token, auth_token)):
                            User = get_user_model()
                            users = User.objects.all()

                            response = []
                            for user in users:
                                response.append({
                                    "id": user.id,
                                    "username": user.username
                                })

                            return JsonResponse({"status": "200", "users": response}, status=200, safe=False)
                        else:
                            return JsonResponse({"status": "403", "message": "Permission token problem"}, status=403, safe=False)
        return JsonResponse({"status": "400", "message": "Bad request cookies"}, status=400, safe=False)
    else:
        return JsonResponse({"status": "405", "message": "Bad request type, use GET method for this route"}, status=405, safe=False)

# util routes


def renew_jwt_token(req):
    if req.body and req.method == "POST":
        if req.COOKIES.get(JWT_TOKEN_COOKIE_NAME):
            old_token = validateJWT(req.COOKIES.get(JWT_TOKEN_COOKIE_NAME))
            if old_token:
                new_token = issueJWT(old_token['userID'])

                response = JsonResponse(
                    {"status": "200", "message": "User authenticated", 'token': new_token}, status=200, safe=False)
                cookie_expiry = datetime.now() + timedelta(days=COOKIE_TIME_TO_LIVE_DAYS)
                response.set_cookie(JWT_TOKEN_COOKIE_NAME, new_token, expires=cookie_expiry)  # nopep8
                return response
            else:
                return JsonResponse({"status": "400", "message": "Invalid or missing "+JWT_TOKEN_COOKIE_NAME+" cookie"}, status=400, safe=False)
        else:
            return JsonResponse({"status": "401", "message": "JWT Cookie not included in request"}, status=401, safe=False)
    else:
        return JsonResponse({"status": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def get_public_cert(req):
    if req.method == "GET":
        return JsonResponse({"status": "200", "public_key": JWT_PUBLIC_KEY}, status=200, safe=False)
    else:
        return JsonResponse({"status": "405", "message": "Bad request type, use GET method for this route"}, status=405, safe=False)


# util functions
def issueJWT(userID):
    tokenInfo = {
        "userID": userID,
        "issued": str(datetime.now()),
        "expires": str(datetime.now() + timedelta(days=COOKIE_TIME_TO_LIVE_DAYS))
    }

    token = jwt.encode(tokenInfo, JWT_PRIVATE_KEY,
                       algorithm='RS512').decode('utf-8')
    return token


def validateJWT(token):
    try:
        payload = jwt.decode(token, JWT_PUBLIC_KEY, algorithms=['RS512'])

        issuedTime = datetime.strptime(
            str(payload['issued']), '%Y-%m-%d %H:%M:%S.%f')
        # check issued time is in the past
        if not (issuedTime < datetime.now()):
            return False

        expiryTime = datetime.strptime(
            str(payload['expires']), '%Y-%m-%d %H:%M:%S.%f')
        # check expiry time is in the future
        if not (expiryTime > datetime.now()):
            return False

        return payload
    except:
        return False


def userIsAdmin(perm_token_payload, auth_token_payload):
    if not (perm_token_payload['userID'] == auth_token_payload['userID']):
        return False

    for role in perm_token_payload['roles']:
        if role['name'] == 'admin':
            return True
    return False
