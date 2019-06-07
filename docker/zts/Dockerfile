FROM athenz-builder AS builder

FROM openjdk:8-jre-alpine

WORKDIR /opt/athenz/zts

COPY --from=builder /opt/athenz/zts .

ENV JAVA_OPTS=''
ENV CLASSPATH='lib/jars/*'
ENV USER_CLASSPATH='/usr/lib/jars/*'
ENV CONF_PATH='conf/zts_server'

# ENV for passwords
ENV ZTS_CERT_JDBC_PASSWORD=''
ENV ZTS_SELF_SIGNER_PRIVATE_KEY_PASSWORD=''
ENV ZTS_ZTS_SSL_KEY_STORE_PASSWORD=''
ENV ZTS_ZTS_SSL_TRUST_STORE_PASSWORD=''
ENV ZTS_SSL_KEY_STORE_PASSWORD=''
ENV ZTS_SSL_TRUST_STORE_PASSWORD=''

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
  "-Dathenz.zts.cert_jdbc_password=${ZTS_CERT_JDBC_PASSWORD}", \
  "-Dathenz.zts.self_signer_private_key_password=${ZTS_SELF_SIGNER_PRIVATE_KEY_PASSWORD}", \
  "-Dathenz.zts.ssl_key_store_password=${ZTS_ZTS_SSL_KEY_STORE_PASSWORD}", \
  "-Dathenz.zts.ssl_trust_store_password=${ZTS_ZTS_SSL_TRUST_STORE_PASSWORD}", \
  "-Djavax.net.ssl.trustStorePassword=${ZTS_ZTS_SSL_TRUST_STORE_PASSWORD}", \
  "-Dathenz.ssl_key_store_password=${ZTS_SSL_KEY_STORE_PASSWORD}", \
  "-Dathenz.ssl_trust_store_password=${ZTS_SSL_TRUST_STORE_PASSWORD}", \
  # main class
  "com.yahoo.athenz.container.AthenzJettyContainer" \
]
