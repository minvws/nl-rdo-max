# syntax=docker/dockerfile:1
# syntax directive is used to enable Docker BuildKit

FROM python:3.11-slim AS base

ARG PROJECT_DIR="/src" \
    NODE_VERSION \
    APP_USER="app" \
    APP_GROUP="app" \
    UID=1000 \
    GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENV MYPYPATH=${PROJECT_DIR}/stubs
ENV NVM_DIR=/home/${APP_USER}/.nvm

RUN apt-get update && \
    apt-get install -y --no-install-recommends make curl libxmlsec1-dev gnupg2 lsb-release && \
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --system ${APP_GROUP} --gid=${GID} && \
    adduser --disabled-password --gecos "" --uid ${UID} --gid ${GID} \
    --home /home/${APP_USER} ${APP_USER}

USER ${APP_USER}

ENV PATH="/usr/local/bin:$PATH"

FROM base AS final

WORKDIR ${PROJECT_DIR}

EXPOSE 8006

COPY --chown=${APP_USER}:${APP_GROUP} ./ ${PROJECT_DIR}

RUN chmod +x /src/entrypoint.sh

ENTRYPOINT ["/src/entrypoint.sh"]
CMD ["python", "-m", "app.main"]
