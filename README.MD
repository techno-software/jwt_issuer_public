# Soo what is this

The gist of this django api is to provide a simple way to manage user logins in your app using JWT. On purpose, it provides very limited capabilities so that it's as reusable as possbile. Here's a quick API endpoint rundown:

## POST routes

### `/auth`
* Requires `username` and `password` to be set in the body of the request in json
* Returns a json with a `status` and a `jwt` field, also sets a `jwt_token` cookie

### `/register`
* Requires `username`, `password` and `email` to be set in the body of the request in json
* Returns a json with a `status` field

### `/update_profile`
* Takes either a `password` or a `email` (or both) in the body of the request in json form. Also requries a valid `jwt_token` cookie to be sent along with the request
* Returns a json with a `status` field

### `/renew_token`
* Send a request with the `jwt_cookie` in the header and get a refreshed one!
* Returns a json with a `status` and `token` field

### `/request_password_reset`
* This requests a password reset code - send a valid `email` in the body of the request in json and you will receive an email with your username and password!
* Returns a json with a `status` field 

### `/reset_password`
* Takes your password reset code from your email as `reset_code` in the body of the request in json form. 
* Returns a new temporary password to use so that you can set a proper one using the `/update_profile` route in a json with a `status` field and a `reset_code` field

## GET routes

### `/liveliness`
Returns the status of the service (`OK`), the current time and the uptime of the process. 

### `/get_public_cert`
Returns the public key that can be used to validate the JWT tokens issues by the server in a json with a `status` field and a `public_key` field

# More info

Don't forget to edit the password reset templates under `jwtController/jwtIssuer/templates`

Don't forget to install your own certificates to use with the web-API

Don't forget to set a sane configuration for CORS, follow guide [here](http://www.srikanthtechnologies.com/blog/python/enable_cors_for_django.aspx)

Don't forget to edit the settings file under `jwtController/jwtController/settings.py`, more specifically:

* EMAIL_BACKEND
* EMAIL_HOST
* EMAIL_PORT
* EMAIL_USE_TLS
* EMAIL_HOST_USER
* EMAIL_FROM_USER
* EMAIL_HOST_PASSWORD

Last and not least, don't forget to run the app in production mode and hook it up to a real database...
