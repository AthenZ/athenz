FROM node:hydrogen-alpine AS builder

RUN set -eux && apk update && apk add --no-cache --update ca-certificates libstdc++ libgcc tini make git bash

WORKDIR /tmp/work

# dependency cache layer
COPY package.json .
RUN npm install

COPY . .

RUN make build

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

FROM node:hydrogen-alpine
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-ui"
LABEL org.label-schema.description="Athenz UI server"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

ARG GID=1001
ARG UID=10001

RUN mkdir -p /var/lib/sia/tokens/msd-api-access && touch /var/lib/sia/tokens/msd-api-access/msd-api-access-token
# add athenz user
RUN addgroup -g ${GID} athenz && \
  adduser -S -D -H -s /sbin/nologin -u ${UID} -G athenz athenz && chown -R athenz:athenz /var/lib/sia/tokens/msd-api-access
USER athenz

WORKDIR /opt/athenz/ui

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /sbin/tini /sbin/tini
COPY --from=builder --chown=${UID}:${GID} /tmp/work /opt/athenz/ui

EXPOSE 443

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["npm", "start"]
