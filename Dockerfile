FROM python:3.10-bullseye

# setup production python env variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install system dependecies
RUN pip install --upgrade pip
RUN apt update -y&&apt upgrade -y

RUN mkdir /project
WORKDIR /project

# setup static files (nginx and startup script)
COPY ./static_files/startup.sh /project/startup.sh
RUN chmod +x /project/startup.sh

# setup application user
RUN adduser --disabled-password appuser

# setup project
COPY requirements.txt /project/
RUN pip3 install -r requirements.txt
COPY ./jwtController /project/jwtController
RUN chown -R appuser /project

# set entrypoint
CMD ["./startup.sh"]