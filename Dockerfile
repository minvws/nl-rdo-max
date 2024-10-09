# syntax=docker/dockerfile:1
# syntax directive is used to enable Docker BuildKit

FROM python:3.10-slim as base

ARG PROJECT_DIR="/src"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt update && \
    apt install -y \
    make \
    curl \
    software-properties-common \
    npm

RUN npm install npm@latest --global && \
    npm install n --global && \
    n latest

WORKDIR ${PROJECT_DIR}

FROM base as final

EXPOSE 8006
WORKDIR ${PROJECT_DIR}

CMD tail -f /dev/null
