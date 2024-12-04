# syntax=docker/dockerfile:1
# syntax directive is used to enable Docker BuildKit

FROM python:3.10-slim AS base

ARG PROJECT_DIR="/src"
ARG NODE_VERSION=20

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NVM_DIR=/root/.nvm

RUN apt update && \
    apt install -y --no-install-recommends make curl && \
    rm -rf /var/lib/apt/lists/*

# Install NVM, Node.js, and npm
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash && \
    . "$NVM_DIR/nvm.sh" && \
    nvm install $NODE_VERSION && \
    nvm use $NODE_VERSION && \
    nvm alias default $NODE_VERSION && \
    npm install -g npm

COPY .npmrc /root/.npmrc
RUN --mount=type=secret,id=github_token \
    sh -c '. $NVM_DIR/nvm.sh && \
            echo "//npm.pkg.github.com/:_authToken=$(cat /run/secrets/github_token)" >> /root/.npmrc'

COPY ./scripts/setup-npm.sh /setup-npm.sh
RUN chmod +x /setup-npm.sh && ./setup-npm.sh

COPY requirements.txt setup.cfg setup.py ./
RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir pip-tools \
    && pip-compile --extra dev \
    && pip-sync \
    && pip install --no-binary lxml==4.9.3 lxml==4.9.3 --force-reinstall \
    && pip install --no-binary xmlsec==1.3.14 xmlsec==1.3.14 --force-reinstall \
    && pip install -e .

FROM base AS final

WORKDIR ${PROJECT_DIR}
EXPOSE 8006

COPY ./ ${PROJECT_DIR}

ENV PATH="$NVM_DIR/versions/node/$NODE_VERSION/bin:$PATH"

RUN chmod +x /src/entrypoint.sh
ENTRYPOINT ["/src/entrypoint.sh"]
CMD ["python", "-m", "app.main"]
