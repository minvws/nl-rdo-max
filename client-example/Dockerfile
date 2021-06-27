FROM node:16

WORKDIR /app
COPY package.json /app/
RUN npm install

COPY index.html /app/
COPY index.js /app/
COPY .env.docker /app/.env


ENV NODE_TLS_REJECT_UNAUTHORIZED='0'

CMD node index.js
