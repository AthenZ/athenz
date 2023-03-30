FROM mariadb:10.5.13
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-zms-db"
LABEL org.label-schema.description="Athenz ZMS Database"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

COPY zms_server.sql /docker-entrypoint-initdb.d/

# In docker env., skip-name-resolve is enable by default. Disable it to allow login with reverse DNS lookup.
# https://github.com/docker-library/mariadb/blob/3b2e52a6a0a525d879053a33886f35d3a5c38603/10.4/Dockerfile#L121
RUN rm /etc/mysql/conf.d/docker.cnf; \
	echo '[mysqld]\nskip-host-cache' > /etc/mysql/conf.d/docker.cnf; \
	sed 's/skip-name-resolve/# skip-name-resolve/g' -i /etc/mysql/my.cnf

ENTRYPOINT ["docker-entrypoint.sh"]

# EXPOSE 3306
CMD ["mysqld"]

HEALTHCHECK --interval=1m --timeout=3s --start-period=10s --retries=3 \
  CMD mysql -sss \
  --host localhost \
  --user=root "--password=${MYSQL_ROOT_PASSWORD}" \
  -e 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = "zms_server"' \
  || exit 1
