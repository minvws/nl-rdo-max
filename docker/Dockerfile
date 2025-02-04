# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.8

FROM python:${PYTHON_VERSION}-bookworm AS base

ARG REMOTE_SOURCE_DIR="/src" \
    LOCAL_SOURCE_DIR="." \
    NODE_VERSION=18 \
    APP_USER="app" \
    APP_GROUP="app" \
    UID=1000 \
    GID=1000 \
    INSTALL_NPM_ASSETS=true
    
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENV MYPYPATH=${PROJECT_DIR}/stubs

RUN apt-get update && \
    apt-get install -y --no-install-recommends make curl libxmlsec1-dev gnupg2 lsb-release && \
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* 

RUN getent group ${APP_GROUP} || groupadd --system ${APP_GROUP} --gid=${GID} && \
    getent passwd ${APP_USER} || adduser --disabled-password --gecos "" --uid ${UID} --gid ${GID} \
    --home /home/${APP_USER} ${APP_USER}

FROM base AS builder

WORKDIR /src

# python environment setup
COPY requirements.txt setup.py setup.cfg ./
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m venv /src/.venv && \
    . /src/.venv/bin/activate && \
    pip install -U pip && \
    pip install pip-tools && \
    pip-compile --extra dev && \
    pip-sync && \
    pip install -e . && \
    pip install --no-binary lxml==4.9.3 lxml==4.9.3 --force-reinstall && \
    pip install --no-binary xmlsec==1.3.14 xmlsec==1.3.14 --force-reinstall

RUN mkdir -p node_modules static/assets

COPY .npmrc scripts/setup-npm.sh vite.config.js package.json package-lock.json ./
COPY resources ./resources

RUN if [ "$INSTALL_NPM_ASSETS" = "true" ]; then \
        chmod +x setup-npm.sh && ./setup-npm.sh || { echo 'setup-npm.sh failed'; exit 1; }; \
        npm run build || { echo 'npm build failed'; exit 1; }; \
    fi

FROM base AS final

ENV PATH="/usr/local/bin:$PATH"

WORKDIR ${REMOTE_SOURCE_DIR}
EXPOSE 8006

COPY --chown=${APP_USER}:${APP_GROUP} ${LOCAL_SOURCE_DIR}/ ${REMOTE_SOURCE_DIR}
COPY --from=builder --chown=${APP_USER}:${APP_GROUP} /src/.venv /src/.venv
COPY --from=builder --chown=${APP_USER}:${APP_GROUP} /src/node_modules /src/node_modules
COPY --from=builder --chown=${APP_USER}:${APP_GROUP} /src/static/assets /src/static/assets

USER ${APP_USER}
RUN chmod +x docker/entrypoint.sh
ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["python", "-m", "app.main"]
