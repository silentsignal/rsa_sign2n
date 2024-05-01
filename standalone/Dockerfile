FROM ubuntu:20.04

RUN apt update && apt install -y python3.8 python3-pip python3-gmpy2 libgmp-dev libmpfr-dev libmpc-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip3 install -r requirements.txt
