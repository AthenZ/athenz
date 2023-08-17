FROM athenz/athenz-builder AS builder

FROM eclipse-temurin:11-jre-focal
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-zts-server"
LABEL org.label-schema.description="Athenz ZTS server"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

ARG GID=1001
ARG UID=10001

RUN apt-get -y install bash

# add athenz user
RUN addgroup --system --gid ${GID} athenz && \
  adduser --system --disabled-password --no-create-home --shell /sbin/nologin --uid ${UID} --ingroup athenz athenz
USER athenz

WORKDIR /opt/athenz/zts

COPY --from=builder /opt/athenz/zts .

ENV JAVA_OPTS=''
ENV CLASSPATH='/opt/athenz/zts/lib/jars/*'
ENV USER_CLASSPATH='/usr/lib/jars/*'
ENV CONF_PATH='/opt/athenz/zts/conf/zts_server'

# ENV for passwords
ENV ZTS_DB_ADMIN_PASS=''
ENV ZTS_KEYSTORE_PASS=''
ENV ZTS_TRUSTSTORE_PASS=''
ENV ZTS_SIGNER_KEYSTORE_PASS=''
ENV ZTS_SIGNER_TRUSTSTORE_PASS=''
ENV ZMS_CLIENT_KEYSTORE_PASS=''
ENV ZMS_CLIENT_TRUSTSTORE_PASS=''

COPY ./docker/zts/docker-entrypoint.sh /usr/local/bin
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# ENV for healthcheck
ENV ZTS_PORT='8443'

HEALTHCHECK --interval=1m --timeout=3s --start-period=10s --retries=3 \
  CMD wget -O - --quiet --tries=1 --no-check-certificate \
  "https://127.0.0.1:${ZTS_PORT}/zts/v1/status" \
  || exit 1
