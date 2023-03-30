FROM node:18.15.0-alpine

ARG NPM_TOKEN

WORKDIR /app

RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > /app/.npmrc

COPY *.json /app
COPY src /app/src

RUN npm install

RUN rm -f /app/.npmrc

RUN npm run build

ENTRYPOINT ["node", "dist/index.js"]
