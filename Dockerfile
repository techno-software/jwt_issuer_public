FROM python:3.9-alpine

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# setup system
RUN pip install --upgrade pip
RUN apk add musl-dev gcc rust cargo libressl-dev postgresql-dev python3-dev libffi-dev bash py3-virtualenv nginx
RUN mkdir /project
WORKDIR /project

# setup nginx
RUN rm /etc/nginx/conf.d/default.conf
COPY ./static_files/nginx.default /etc/nginx/conf.d/default.conf

# setup virtualenv
RUN virtualenv py-env
RUN bash -c "source py-env/bin/activate"

# setup project
COPY requirements.txt /project/
RUN pip3 install -r requirements.txt
COPY ./jwtController /project/jwtController