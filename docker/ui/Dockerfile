FROM node:10.9-alpine AS builder
LABEL maintainer "kpango <i.can.feel.gravity@gmail.com>"

RUN set -eux && apk update && apk add --no-cache --update ca-certificates libstdc++ libgcc tini

WORKDIR /tmp/work

COPY . .

RUN make

RUN rm -rf scripts \
    && rm -rf test \
    && rm -rf package.json \
    && rm -rf package-lock.json \
    && rm -rf Gruntfile.js \
    && rm -rf Makefile \
    && rm -rf eslint.json \
    && rm -rf pom.xml \
    && rm -rf rdl-api.md \
    && rm -rf README.md

EXPOSE 9443

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["npm", "start"]
