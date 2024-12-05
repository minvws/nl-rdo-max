# syntax=docker/dockerfile:1
# syntax directive is used to enable Docker BuildKit

FROM python:3.11-slim AS base

ARG PROJECT_DIR="/src"
ARG NODE_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NVM_DIR=/root/.nvm

RUN apt update && \
    apt install -y --no-install-recommends make curl libxmlsec1-dev && \
    rm -rf /var/lib/apt/lists/*

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash && \
    . "$NVM_DIR/nvm.sh" && \
    nvm install $NODE_VERSION && \
    nvm use $NODE_VERSION && \
    nvm alias default $NODE_VERSION && \
    npm install -g npm

ENV PATH="$NVM_DIR/versions/node/$NODE_VERSION/bin:$PATH"

COPY .npmrc /root/.npmrc
RUN --mount=type=secret,id=github_token \
    sh -c '. $NVM_DIR/nvm.sh && \
            echo "//npm.pkg.github.com/:_authToken=$(cat /run/secrets/github_token)" >> /root/.npmrc'

COPY ./scripts/setup-npm.sh /setup-npm.sh
RUN chmod +x /setup-npm.sh && ./setup-npm.sh

FROM base AS final

WORKDIR ${PROJECT_DIR}
EXPOSE 8006

COPY ./ ${PROJECT_DIR}

RUN chmod +x /src/entrypoint.sh
ENTRYPOINT ["/src/entrypoint.sh"]
CMD ["python", "-m", "app.main"]
