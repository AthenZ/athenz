FROM athenz-mvn-base AS mvn
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-cli-util"
LABEL org.label-schema.description="All in one image containing all Athenz CLI utilities"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

# install base go from apk
RUN apk add --no-cache --virtual .build-deps bash gcc musl-dev openssl make git

# get latest go from its own image, since its not available in apk
COPY --from=golang:1.17.5-alpine /usr/local/go/ /usr/local/go/

ENV GOPATH="/root/go"
WORKDIR ${GOPATH}/src/github.com/AthenZ/athenz
COPY . .

# cache maven dependency
# RUN mvn dependency:go-offline -DexcludeGroupIds="com.yahoo.athenz"

RUN mkdir -p "${GOPATH}/bin"

# add $GOPATH/bin and latest go bin to path
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

# fix to have rdl binary available to be used by client generators.
RUN go get -d github.com/ardielle/ardielle-tools/... && go install github.com/ardielle/ardielle-tools/... \
    && mkdir -p /root/go/src/github.com/AthenZ/athenz/clients/go/zms/bin && cp /root/go/bin/rdl /root/go/src/github.com/AthenZ/athenz/clients/go/zms/bin \
    && mkdir -p /root/go/src/github.com/AthenZ/athenz/clients/go/zts/bin && cp /root/go/bin/rdl /root/go/src/github.com/AthenZ/athenz/clients/go/zts/bin \
    && mkdir -p /root/go/src/github.com/AthenZ/athenz/clients/go/msd/bin && cp /root/go/bin/rdl /root/go/src/github.com/AthenZ/athenz/clients/go/msd/bin

RUN GO111MODULE=on \
  CGO_ENABLED=0 \
  CGO_CXXFLAGS="-g -Ofast -march=native" \
  CGO_FFLAGS="-g -Ofast -march=native" \
  CGO_LDFLAGS="-g -Ofast -march=native" \
  GOOS=$(go env GOOS) \
  GOARCH=$(go env GOARCH) \
  mvn -B install -Dmaven.test.skip=true -Djacoco.skip=true \
  -pl core/zms \
  -pl core/zts \
  -pl core/msd \
  # go projects
  -pl rdl/rdl-gen-athenz-go-client \
  -pl clients/go/zms \
  -pl clients/go/zts \
  -pl clients/go/msd \
  -pl libs/go/zmscli \
  -pl libs/go/athenzutils \
  -pl libs/go/athenzconf \
  -pl utils/zms-cli \
  -pl utils/athenz-conf \
  -pl utils/zts-accesstoken \
  -pl utils/zts-rolecert \
  -pl utils/zts-svccert \
  -pl assembly/utils

# Start From Scratch For Running Environment
FROM scratch
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-utils"
LABEL org.label-schema.description="athenz-utils CLIs"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF
ENV APP_NAME athenz-utils
COPY --from=mvn /root/go/src/github.com/AthenZ/athenz/utils/zms-cli/target/linux/zms-cli /usr/bin/zms-cli
COPY --from=mvn /root/go/src/github.com/AthenZ/athenz/utils/zts-accesstoken/target/linux/zts-accesstoken /usr/bin/zts-accesstoken
COPY --from=mvn /root/go/src/github.com/AthenZ/athenz/utils/zts-svccert/target/linux/zts-svccert /usr/bin/zts-svccert
COPY --from=mvn /root/go/src/github.com/AthenZ/athenz/utils/zts-rolecert/target/linux/zts-rolecert /usr/bin/zts-rolecert
USER ${APP_NAME}:${APP_NAME}
ENTRYPOINT ["/usr/bin/zms-cli"]