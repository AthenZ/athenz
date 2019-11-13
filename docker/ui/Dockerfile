FROM node:10.17.0-alpine AS builder

RUN set -eux && apk update && apk add --no-cache --update ca-certificates libstdc++ libgcc tini make git

WORKDIR /tmp/work

# dependency cache layer
COPY package.json .
RUN npm install

COPY . .

RUN make

RUN rm -rf scripts \
    && rm -rf test \
    && rm -rf Gruntfile.js \
    && rm -rf Makefile \
    && rm -rf eslint.json \
    && rm -rf pom.xml \
    && rm -rf rdl-api.md \
    && rm -rf README.md

FROM node:10.17.0-alpine

WORKDIR /opt/athenz/ui

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /sbin/tini /sbin/tini
COPY --from=builder /tmp/work /opt/athenz/ui

EXPOSE 443

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["npm", "start"]
