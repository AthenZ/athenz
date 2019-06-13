FROM alpine:latest

# install openssl
RUN apk add --no-cache --update openssl

WORKDIR /

ENTRYPOINT [ "openssl" ]
CMD [ "version", "-a" ]
