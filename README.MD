# What this application does

The gist of this django api is to provide a simple way to manage user logins in your app using JWT. On purpose, it provides very limited capabilities so that it's as reusable as possbile. This version of the authentication API is designed to be used in managed systems, thus the removal of self-serve password resets and the addition of admin password reset. Here's a quick API endpoint rundown:

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

### `/reset_user_password`
* Send a request with valid `jwt_cookie` and `jwt_permissions` cookies in the header as well as an `jwt_id` and `new_password` in the body for the user will get the new password 
* Returns a json with a `status` field

## GET routes

### `/liveliness`
Returns the status of the service (`OK`), the current time and the uptime of the process. 

### `/get_public_cert`
Returns the public key that can be used to validate the JWT tokens issues by the server in a json with a `status` field and a `public_key` field

### `/all_users`
* Send a request with valid `jwt_cookie` and `jwt_permissions` cookies in the header and receive a list of all userIDs registered in the system 
* Returns a json with a `data` field

# More info

Don't forget to edit the password reset templates under `jwtController/jwtIssuer/templates`

Don't forget to install your own certificates to use with the web-API

Don't forget to set a sane configuration for CORS, follow guide [here](http://www.srikanthtechnologies.com/blog/python/enable_cors_for_django.aspx)
