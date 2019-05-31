FROM alpine

# install openssl
RUN apk add --no-cache --update openssl

WORKDIR /

COPY gen-certs.sh .

VOLUME [ "/docker" ]
ENTRYPOINT ["/gen-certs.sh"]
