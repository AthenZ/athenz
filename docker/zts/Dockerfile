FROM athenz-builder AS builder

FROM openjdk:8-jre-alpine

WORKDIR /opt/athenz/zts

COPY --from=builder /opt/athenz/zts .

# ENV EXTRA_CLASSPATH='lib/jars/extra/*'
ENV JAVA_OPTS=''
ENV EXTRA_CLASSPATH=''
ENV CLASSPATH='lib/jars/*'
ENV CONF_PATH='${CONF_PATH}'

RUN [[ ! -z "${EXTRA_CLASSPATH}" ]] && CLASSPATH=${CLASSPATH}:${EXTRA_CLASSPATH}

ENTRYPOINT ["java"]
CMD ["${JAVA_OPTS}", "-classpath", "${CLASSPATH}", "-Dathenz.root_dir=.", "-Dathenz.zts.root_dir=.", "-Dathenz.prop_file=${CONF_PATH}/athenz.properties", "-Dathenz.zts.prop_file=${CONF_PATH}/zts.properties", "-Dlogback.configurationFile=${CONF_PATH}/logback.xml", "com.yahoo.athenz.container.AthenzJettyContainer"]
