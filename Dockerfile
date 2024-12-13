# syntax=docker/dockerfile:1
# syntax directive is used to enable Docker BuildKit

FROM python:3.8-bookworm AS base

ARG REMOTE_SOURCE_DIR="/src" \
    LOCAL_SOURCE_DIR="." \
    NODE_VERSION=18 \
    APP_USER="app" \
    APP_GROUP="app" \
    UID=1000 \
    GID=1000
    
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENV MYPYPATH=${PROJECT_DIR}/stubs
ENV NVM_DIR=/home/${APP_USER}/.nvm
ENV INSTALL_NPM_ASSETS=true

RUN apt-get update && \
    apt-get install -y --no-install-recommends make curl libxmlsec1-dev gnupg2 lsb-release && \
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* 

RUN getent group ${APP_GROUP} || groupadd --system ${APP_GROUP} --gid=${GID} && \
    getent passwd ${APP_USER} || adduser --disabled-password --gecos "" --uid ${UID} --gid ${GID} \
    --home /home/${APP_USER} ${APP_USER}


USER ${APP_USER}

ENV PATH="/usr/local/bin:$PATH"

FROM base AS final

WORKDIR ${REMOTE_SOURCE_DIR}

EXPOSE 8006

COPY --chown=${APP_USER}:${APP_GROUP} ${LOCAL_SOURCE_DIR}/ ${REMOTE_SOURCE_DIR}

RUN chmod +x /src/entrypoint.sh

ENTRYPOINT ["/src/entrypoint.sh"]
CMD ["python", "-m", "app.main"]
