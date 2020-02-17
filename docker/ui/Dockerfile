FROM node:10.19.0-alpine AS builder

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

FROM node:10.19.0-alpine
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-ui"
LABEL org.label-schema.description="Athenz UI server"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/yahoo/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

ARG GID=1001
ARG UID=10001

# add athenz user
RUN addgroup -g ${GID} athenz && \
  adduser -S -D -H -s /sbin/nologin -u ${UID} -G athenz athenz
USER athenz

WORKDIR /opt/athenz/ui

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /sbin/tini /sbin/tini
COPY --from=builder /tmp/work /opt/athenz/ui

EXPOSE 443

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["npm", "start"]
