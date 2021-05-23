from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponseRedirect
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from django.template import Context
from .models import *

import jwt
from datetime import datetime, timedelta
import json
import os.path as path
import re
import random
import string
import time

startTime = time.time()
rootDir = path.abspath(path.join(__file__, "../../../certs"))
JWT_PRIVATE_KEY = open(path.join(rootDir, "private.pem")).read()
JWT_PUBLIC_KEY = open(path.join(rootDir, "public.pem")).read()

RESET_PASS_EMAIL_TEXT_TEMPLATE = get_template('reset_password.txt')
RESET_PASS_EMAIL_HTML_TEMPLATE = get_template('reset_password.html')

COOKIE_TIME_TO_LIVE_DAYS = 14


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
            return JsonResponse({"code": "400", "message": "Bad request body"}, status=400, safe=False)

        if user is not None:
            token = issueJWT(user.id)

            response = JsonResponse(
                {"code": "200", "message": "User authenticated", 'token': token}, status=200, safe=False)
            cookie_expiry = datetime.now() + timedelta(days=COOKIE_TIME_TO_LIVE_DAYS)
            response.set_cookie("jwt_token", token, expires=cookie_expiry)
            return response
        else:
            return JsonResponse({"code": "403", "message": "User not authenticated"}, status=403, safe=False)

    else:
        return JsonResponse({"code": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def register(req):
    if req.body and req.method == "POST":
        try:
            obj = json.loads(req.body)
            username = obj['username']
            email = obj['email']
            password = obj['password']
        except:
            return JsonResponse({"code": "400", "message": "Bad request"}, status=400, safe=False)

        emailStatus = validateEmail(email)
        if (emailStatus == 0):
            pass
        if (emailStatus == 1):
            return JsonResponse({"code": "400", "message": "Invalid email"}, status=400, safe=False)
        if (emailStatus == 2):
            return JsonResponse({"code": "400", "message": "Email already in use"}, status=400, safe=False)

        try:
            if User.objects.get(username=username):
                return JsonResponse({"code": "400", "message": "Username already in use"}, status=400, safe=False)
        except:
            pass

        user = User.objects.create_user(username, email, password)
        user.save()
        return JsonResponse({"code": "200", "message": "User registered"}, status=200, safe=False)
    else:
        return JsonResponse({"code": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def update_profile(req):
    if req.body and req.method == "POST":
        if req.COOKIES.get('jwt_token'):
            token = validateJWT(req.COOKIES.get('jwt_token'))
            if token:
                # try to update email
                try:
                    obj = json.loads(req.body)
                    email = obj['email']
                    emailStatus = validateEmail(email)
                    if (emailStatus == 0):
                        User.objects.get(
                            id=token['userID']).update(email=email)
                    if (emailStatus == 1):
                        return JsonResponse({"code": "400", "message": "Invalid email"}, status=400, safe=False)
                    if (emailStatus == 2):
                        return JsonResponse({"code": "400", "message": "Email already in use"}, status=400, safe=False)
                except:
                    pass

                # try to update password
                try:
                    obj = json.loads(req.body)
                    password = obj['password']
                    user = User.objects.get(id=token['userID'])
                    user.set_password(password)
                    user.save()
                except:
                    pass

                return JsonResponse({"code": "200"}, status=200, safe=False)
        return JsonResponse({"code": "400", "message": "Invalid or missing jwt_token cookie"}, status=400, safe=False)
    else:
        return JsonResponse({"code": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def renew_jwt_token(req):
    if req.body and req.method == "POST":
        if req.COOKIES.get('jwt_token'):
            old_token = validateJWT(req.COOKIES.get('jwt_token'))
            if old_token:
                new_token = issueJWT(old_token['userID'])

                response = JsonResponse(
                    {"code": "200", "message": "User authenticated", 'token': new_token}, status=200, safe=False)
                response.set_cookie("jwt_token", new_token)
                return response
            else:
                return JsonResponse({"code": "400", "message": "Invalid or missing jwt_token cookie"}, status=400, safe=False)
    else:
        return JsonResponse({"code": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def request_password_reset(req):
    if req.body and req.method == "POST":
        try:
            obj = json.loads(req.body)
            email = obj['email']
        except:
            return JsonResponse({"code": "400", "message": "Bad request"}, status=400, safe=False)

        emailStatus = validateEmail(email)
        if (emailStatus == 0):
            return JsonResponse({"code": "404", "message": "Email not in use"}, status=404, safe=False)
        if (emailStatus == 1):
            return JsonResponse({"code": "400", "message": "Invalid email"}, status=400, safe=False)
        if (emailStatus == 2):
            user = User.objects.get(email=email)

            password_reset_request_entry = None
            # try to get existing object to overwrite it if it exists
            try:
                password_reset_request_entry = PasswordResetRequest.objects.get(
                    forUser=user)
            except:
                pass

            if password_reset_request_entry:
                password_reset_request_entry.reset_code = generate_password_reset_code(
                    12)
                password_reset_request_entry.sent_to_email = user.email
                password_reset_request_entry.time_sent = datetime.now()

            # else create new object
            else:
                password_reset_request_entry = PasswordResetRequest(
                    forUser=user,
                    reset_code=generate_password_reset_code(12),
                    sent_to_email=user.email,
                    time_sent=datetime.now()
                )

            password_reset_request_entry.save()

            # send the email
            subject, from_email, to = 'Password Reset', settings.EMAIL_FROM_USER, user.email

            context = {
                'username': user.username,
                'reset_code': password_reset_request_entry.reset_code
            }

            text_content = RESET_PASS_EMAIL_TEXT_TEMPLATE.render(context)
            html_content = RESET_PASS_EMAIL_HTML_TEMPLATE.render(context)

            msg = EmailMultiAlternatives(
                subject, text_content, from_email, [to])

            msg.attach_alternative(html_content, "text/html")
            msg.send()

            return JsonResponse({"code": "200", "message": "Password reset link was sent", "email": password_reset_request_entry.sent_to_email}, status=200, safe=False)

    else:
        return JsonResponse({"code": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def reset_password(req):
    if req.body and req.method == "POST":
        try:
            obj = json.loads(req.body)
            code = obj['reset_code']
        except:
            return JsonResponse({"code": "400", "message": "Bad request"}, status=400, safe=False)

        reset_entry = None
        try:
            reset_entry = PasswordResetRequest.objects.get(reset_code=code)
        except:
            return JsonResponse({"code": "500", "message": "Password reset code invalid"}, status=500, safe=False)

        user = reset_entry.forUser
        newPass = generate_password_reset_code(6)
        user.set_password(newPass)
        user.save()

        reset_entry.delete()

        return JsonResponse({"code": "200", "message": "New password generated. Change your password ASAP using the update route", "password": newPass}, status=200, safe=False)
    else:
        return JsonResponse({"code": "405", "message": "Bad request type, use POST method with json body for this route"}, status=405, safe=False)


def get_public_cert(req):
    if req.method == "GET":
        return JsonResponse({"code": "200", "public_key": JWT_PUBLIC_KEY}, status=200, safe=False)
    else:
        return JsonResponse({"code": "405", "message": "Bad request type, use GET method for this route"}, status=405, safe=False)


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


# returns 1 if email string is invalid, 2 if email is already in use and 0 if email is available for use
def validateEmail(email):
    # check valid format
    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if not (re.search(regex, email)):
        return 1

    # check if in use
    try:
        if User.objects.get(email=email):
            return 2
    except:
        pass

    # return 0 if all is good
    return 0


def generate_password_reset_code(length):
    # choose from all lowercase letter
    letters = string.ascii_uppercase
    code_ok = False

    # very sorry for this, this language doesn't have a do-while loop :/
    while not code_ok:
        # generate reset code
        result_str = ''.join(random.choice(letters) for i in range(length))
        code_ok = True

        # check if code is unique:
        try:
            if PasswordResetRequest.objects.get(reset_code=result_str):
                code_ok = False
        except:
            pass

    return result_str
