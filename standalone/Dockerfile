FROM ubuntu:20.04

RUN apt update
RUN apt install -y python3.8 python3-pip python3-gmpy2

WORKDIR /app

COPY . . 

RUN pip3 install -r requirements.txt
