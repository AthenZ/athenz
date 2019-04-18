FROM athenz-builder AS builder

FROM openjdk:8-jre-alpine

WORKDIR /opt/athenz/zts

COPY --from=builder /opt/athenz/zts .

ENV JAVA_OPTS=''
ENV CLASSPATH='lib/jars/*'
ENV USER_CLASSPATH='/usr/lib/jars/*'
ENV CONF_PATH='conf/zts_server'

ENTRYPOINT ["sh", "-c", "eval $0 $@", "java"]
CMD ["${JAVA_OPTS}", "-classpath", "${CLASSPATH}:${USER_CLASSPATH}", "-Dathenz.root_dir=.", "-Dathenz.zts.root_dir=.", "-Dathenz.prop_file=${CONF_PATH}/athenz.properties", "-Dathenz.zts.prop_file=${CONF_PATH}/zts.properties", "-Dlogback.configurationFile=${CONF_PATH}/logback.xml", "com.yahoo.athenz.container.AthenzJettyContainer"]
