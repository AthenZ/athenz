FROM athenz-builder AS builder

FROM openjdk:8-jre-alpine

WORKDIR /opt/athenz/zms

COPY --from=builder /opt/athenz/zms .

# ENV EXTRA_CLASSPATH='lib/jars/extra/*'
ENV JAVA_OPTS=''
ENV EXTRA_CLASSPATH=''
ENV CLASSPATH='lib/jars/*'
ENV CONF_PATH='conf/zms_server'

RUN [[ ! -z "${EXTRA_CLASSPATH}" ]] && CLASSPATH=${CLASSPATH}:${EXTRA_CLASSPATH}

ENTRYPOINT ["java"]
CMD ["${JAVA_OPTS}", "-classpath", "${CLASSPATH}", "-Dathenz.prop_file=${CONF_PATH}/athenz.properties", "-Dathenz.zms.prop_file=${CONF_PATH}/zms.properties", "-Dlogback.configurationFile=${CONF_PATH}/logback.xml", "com.yahoo.athenz.container.AthenzJettyContainer"]
