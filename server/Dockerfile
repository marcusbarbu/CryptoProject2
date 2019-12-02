FROM ubuntu:latest
MAINTAINER __mgb__


RUN apt-get update && apt-get install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa && apt-get update && apt-get install -y python3.6

WORKDIR /root
COPY serve.py serve.py

EXPOSE 1234
CMD python3 serve.py