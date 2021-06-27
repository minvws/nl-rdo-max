FROM python:3.8-slim-buster


RUN apt-get update \
    && apt-get install -y \
        gcc \
        gnutls-bin \
        libpq-dev \
        libxml2-dev \
        libxml2 \
        libxmlsec1 \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        build-essential \
        pkg-config \
        python3-dev \
        git

COPY requirements.in /app/requirements.in
COPY requirements-dev.in /app/requirements-dev.in

WORKDIR /app

RUN pip install -U pip pip-tools setuptools wheel

RUN python3 -m piptools compile /app/requirements.in
RUN python3 -m piptools compile /app/requirements-dev.in

RUN pip install -Ur requirements.txt \
    && pip install -Ur requirements-dev.txt \
    && pip uninstall pyop -y \
    && pip install git+https://github.com/maxxiefjv/pyop.git@propose-changes-redis

COPY . /app

ARG PORT=8006
ENV PORT=${PORT}
EXPOSE ${PORT}

ARG SSL_KEY=./secrets/ssl/private/inge6.localdev.key
ENV SSL_KEY=${SSL_KEY}

ARG SSL_CERT=./secrets/ssl/certs/inge6.localdev.crt
ENV SSL_CERT=${SSL_CERT}

CMD python3 -m uvicorn inge6.main:app --debug --host 0.0.0.0 --port ${PORT} --ssl-keyfile ${SSL_KEY} --ssl-certfile ${SSL_CERT} --reload
