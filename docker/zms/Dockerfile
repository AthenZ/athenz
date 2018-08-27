FROM athenz-builder AS builder

FROM openjdk:8-jre-alpine

WORKDIR /opt/athenz/zms

COPY --from=builder /opt/athenz/zms .


ENTRYPOINT ["java"]
CMD ["-classpath", "lib/jars/*", "-Dathenz.prop_file=conf/zms_server/athenz.properties", "-Dathenz.zms.prop_file=conf/zms_server/zms.properties", "-Dlogback.configurationFile=conf/zms_server/logback.xml", "com.yahoo.athenz.container.AthenzJettyContainer"]

