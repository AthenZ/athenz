FROM athenz/athenz-builder AS builder

FROM eclipse-temurin:11-jre-focal
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-zms-server"
LABEL org.label-schema.description="Athenz ZMS server"
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

WORKDIR /opt/athenz/zms

COPY --from=builder /opt/athenz/zms .

ENV JAVA_OPTS=''
ENV CLASSPATH='/opt/athenz/zms/lib/jars/*'
ENV USER_CLASSPATH='/usr/lib/jars/*'
ENV CONF_PATH='/opt/athenz/zms/conf/zms_server'

# ENV for passwords
ENV ZMS_DB_ADMIN_PASS=''
ENV ZMS_RODB_ADMIN_PASS=''
ENV ZMS_KEYSTORE_PASS=''
ENV ZMS_TRUSTSTORE_PASS=''

COPY ./docker/zms/docker-entrypoint.sh /usr/local/bin
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# ENV for healthcheck
ENV ZMS_PORT='4443'

HEALTHCHECK --interval=1m --timeout=3s --start-period=10s --retries=3 \
  CMD wget -O - --quiet --tries=1 --no-check-certificate \
  "https://127.0.0.1:${ZMS_PORT}/zms/v1/status" \
  || exit 1
