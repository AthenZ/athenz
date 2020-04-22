FROM athenz-builder AS builder

FROM adoptopenjdk/openjdk8:alpine-jre
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-zts-server"
LABEL org.label-schema.description="Athenz ZTS server"
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

WORKDIR /opt/athenz/zts

COPY --from=builder /opt/athenz/zts .

ENV JAVA_OPTS=''
ENV CLASSPATH='lib/jars/*'
ENV USER_CLASSPATH='/usr/lib/jars/*'
ENV CONF_PATH='conf/zts_server'

# ENV for passwords
ENV ZTS_DB_ADMIN_PASS=''
ENV ZTS_KEYSTORE_PASS=''
ENV ZTS_TRUSTSTORE_PASS=''
ENV ZTS_SIGNER_KEYSTORE_PASS=''
ENV ZTS_SIGNER_TRUSTSTORE_PASS=''
ENV ZMS_CLIENT_KEYSTORE_PASS=''
ENV ZMS_CLIENT_TRUSTSTORE_PASS=''

ENTRYPOINT ["sh", "-c", "eval $0 $@", "java"]
CMD [ \
  "${JAVA_OPTS}", \
  "-classpath", "${CLASSPATH}:${USER_CLASSPATH}", \
  "-Dathenz.root_dir=.", \
  "-Dathenz.zts.root_dir=.", \
  "-Dathenz.prop_file=${CONF_PATH}/athenz.properties", \
  "-Dathenz.zts.prop_file=${CONF_PATH}/zts.properties", \
  "-Dlogback.configurationFile=${CONF_PATH}/logback.xml", \
  # system properties for passwords
  "-Dathenz.zts.cert_jdbc_password=${ZTS_DB_ADMIN_PASS}", \
  "-Dathenz.ssl_key_store_password=${ZTS_KEYSTORE_PASS}", \
  "-Dathenz.ssl_trust_store_password=${ZTS_TRUSTSTORE_PASS}", \
  "-Dathenz.zts.keystore_signer.keystore_password=${ZTS_SIGNER_KEYSTORE_PASS}", \
  "-Dathenz.zts.ssl_key_store_password=${ZTS_SIGNER_KEYSTORE_PASS}", \
  "-Dathenz.zts.ssl_trust_store_password=${ZTS_SIGNER_TRUSTSTORE_PASS}", \
  "-Djavax.net.ssl.trustStorePassword=${ZTS_SIGNER_TRUSTSTORE_PASS}", \
  "-Dathenz.zms.client.keystore_password=${ZMS_CLIENT_KEYSTORE_PASS}", \
  "-Dathenz.zms.client.truststore_password=${ZMS_CLIENT_TRUSTSTORE_PASS}", \
  # main class
  "com.yahoo.athenz.container.AthenzJettyContainer" \
]

# ENV for healthcheck
ENV ZTS_PORT='8443'

HEALTHCHECK --interval=1m --timeout=3s --start-period=10s --retries=3 \
  CMD wget -O - --quiet --tries=1 --no-check-certificate \
  "https://127.0.0.1:${ZTS_PORT}/zts/v1/status" \
  || exit 1
