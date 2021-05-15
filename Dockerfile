FROM python:3.9-buster 

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# setup system
RUN pip install --upgrade pip
RUN apt-get update && apt-get install -y python3-dev musl-dev bash virtualenv nginx
RUN mkdir /project
WORKDIR /project

# setup virtualenv
RUN virtualenv py-env
RUN bash -c "source py-env/bin/activate"

# setup nginx
RUN rm /etc/nginx/sites-available/default
COPY ./static_files/nginx.default /etc/nginx/sites-available/default
RUN service nginx start

# setup project
COPY requirements.txt /project/
RUN pip3 install -r requirements.txt
COPY ./jwtController /project/jwtController

