#!/bin/sh
cd /project/jwtController
python3 manage.py makemigrations
python3 manage.py migrate
gunicorn jwtController.wsgi:application --bind 0.0.0.0:8000 -w 8
