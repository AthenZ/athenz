FROM node:12.16.2-alpine AS builder

RUN set -eux && apk update && apk add --no-cache --update ca-certificates libstdc++ libgcc tini make git

WORKDIR /tmp/work

# dependency cache layer
COPY package.json .
RUN npm install

COPY . .

RUN make

RUN rm -rf scripts \
    && rm -rf __mocks__ \
    && rm -rf .editorconfig \
    && rm -rf .env \
    && rm -rf .istanbul.yml \
    && rm -rf .npmrc \
    && rm -rf .prettierrc \
    && rm -rf jest.config.js \
    && rm -rf pm2.config.js \
    && rm -rf athenz-ui.spec \
    && rm -rf Makefile \
    && rm -rf pom.xml \
    && rm -rf README.md

FROM node:12.16.2-alpine

WORKDIR /opt/athenz/ui

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /sbin/tini /sbin/tini
COPY --from=builder /tmp/work /opt/athenz/ui

EXPOSE 443

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["npm", "start"]
