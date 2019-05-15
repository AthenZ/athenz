FROM athenz-builder AS builder

FROM openjdk:8-jre-alpine

WORKDIR /opt/athenz/zms

# only useful if UserAuthority.java is used
# RUN apk add musl linux-pam linux-pam-dev
RUN apk add --update linux-pam && \
    rm -rf /var/cache/apk/*

COPY --from=builder /opt/athenz/zms .

ENV JAVA_OPTS=''
ENV CLASSPATH='lib/jars/*'
ENV USER_CLASSPATH='/usr/lib/jars/*'
ENV CONF_PATH='conf/zms_server'

ENTRYPOINT ["sh", "-c", "eval $0 $@", "java"]
CMD ["${JAVA_OPTS}", "-classpath", "${CLASSPATH}:${USER_CLASSPATH}", "-Dathenz.prop_file=${CONF_PATH}/athenz.properties", "-Dathenz.zms.prop_file=${CONF_PATH}/zms.properties", "-Dlogback.configurationFile=${CONF_PATH}/logback.xml", "com.yahoo.athenz.container.AthenzJettyContainer"]
