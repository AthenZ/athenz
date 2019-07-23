FROM alpine:latest

RUN apk add --no-cache --update mysql-client

WORKDIR /usr/bin
COPY wait-for-mysql.sh .

ENV MYSQL_PWD=''

ENTRYPOINT [ "wait-for-mysql.sh" ]
