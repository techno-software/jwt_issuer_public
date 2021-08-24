FROM python:3.9-alpine

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# setup system
RUN pip install --upgrade pip
RUN apk --no-cache --update upgrade
RUN apk add musl-dev gcc rust cargo python3-dev openssl-dev postgresql-dev libffi-dev py3-virtualenv nginx alpine-sdk
RUN mkdir /project
WORKDIR /project

# setup static files (nginx and startup script)
COPY ./static_files/nginx.default /etc/nginx/conf.d/default.conf
COPY ./static_files/startup.sh /project/startup.sh
RUN chmod +x /project/startup.sh

# setup project
COPY requirements.txt /project/
RUN pip3 install -r requirements.txt
COPY ./jwtController /project/jwtController

# setup application user
RUN adduser --disabled-password appuser
RUN chown -R appuser /project

# set entrypoint
CMD ["./startup.sh"]