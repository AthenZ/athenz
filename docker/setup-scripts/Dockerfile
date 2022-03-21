FROM athenz-conf AS athenz-conf

FROM athenz-cli-util AS athenz-utils

FROM adoptopenjdk/openjdk8:alpine-jre
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-setup-env"
LABEL org.label-schema.description="Athenz bootstrap setup ENV"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

COPY --from=athenz-conf /usr/bin/athenz-conf /usr/bin/athenz-conf
COPY --from=athenz-utils /usr/bin/zms-cli /usr/bin/zms-cli
COPY --from=athenz-utils /usr/bin/zts-accesstoken /usr/bin/zts-accesstoken
COPY --from=athenz-utils /usr/bin/zts-svccert /usr/bin/zts-svccert
COPY --from=athenz-utils /usr/bin/zts-rolecert /usr/bin/zts-rolecert

# coreutils: base64
# ncurses: tput
RUN apk update && \
    apk add --no-cache coreutils && \
    apk add --no-cache ncurses && \
    apk add --no-cache git && \
    apk add --no-cache curl && \
    apk add --no-cache tree && \
    apk add --no-cache openssl && \
    apk add --no-cache jq && \
    rm -rf /var/cache/apk/*

# RUN mkdir /athenz
WORKDIR /athenz

CMD [ "echo", "This is a docker image for Athenz setup" ]
