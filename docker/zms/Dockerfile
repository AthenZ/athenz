FROM athenz-builder AS builder

FROM adoptopenjdk/openjdk8:alpine-jre
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-zms-server"
LABEL org.label-schema.description="Athenz ZMS server"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/yahoo/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF
# LABEL maintainer "YJ Athenz Team <>"

ARG GID=1001
ARG UID=10001

# add athenz user
RUN addgroup -g ${GID} athenz && \
  adduser -S -D -H -s /sbin/nologin -u ${UID} -G athenz athenz
USER athenz

WORKDIR /opt/athenz/zms

COPY --from=builder /opt/athenz/zms .

ENV JAVA_OPTS=''
ENV CLASSPATH='lib/jars/*'
ENV USER_CLASSPATH='/usr/lib/jars/*'
ENV CONF_PATH='conf/zms_server'

# ENV for passwords
ENV ZMS_DB_ADMIN_PASS=''
ENV ZMS_RODB_ADMIN_PASS=''
ENV ZMS_KEYSTORE_PASS=''
ENV ZMS_TRUSTSTORE_PASS=''

ENTRYPOINT ["sh", "-c", "eval $0 $@", "java"]
CMD [ \
  "${JAVA_OPTS}", \
  "-classpath", "${CLASSPATH}:${USER_CLASSPATH}", \
  "-Dathenz.prop_file=${CONF_PATH}/athenz.properties", \
  "-Dathenz.zms.prop_file=${CONF_PATH}/zms.properties", \
  "-Dlogback.configurationFile=${CONF_PATH}/logback.xml", \
  # system properties for passwords
  "-Dathenz.zms.jdbc_password=${ZMS_DB_ADMIN_PASS}", \
  "-Dathenz.zms.jdbc_ro_password=${ZMS_RODB_ADMIN_PASS}", \
  "-Dathenz.ssl_key_store_password=${ZMS_KEYSTORE_PASS}", \
  "-Dathenz.ssl_trust_store_password=${ZMS_TRUSTSTORE_PASS}", \
  # main class
  "com.yahoo.athenz.container.AthenzJettyContainer" \
]

# ENV for healthcheck
ENV ZMS_PORT='4443'

HEALTHCHECK --interval=1m --timeout=3s --start-period=10s --retries=3 \
  CMD wget -O - --quiet --tries=1 --no-check-certificate \
  "https://127.0.0.1:${ZMS_PORT}/zms/v1/status" \
  || exit 1
