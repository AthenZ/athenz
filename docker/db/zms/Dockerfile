FROM mariadb:latest

COPY zms_server.sql /docker-entrypoint-initdb.d/

# In docker env., skip-name-resolve is enable by default. Disable it to allow login with reverse DNS lookup.
# https://github.com/docker-library/mariadb/blob/3b2e52a6a0a525d879053a33886f35d3a5c38603/10.4/Dockerfile#L121
RUN rm /etc/mysql/conf.d/docker.cnf; \
	echo '[mysqld]\nskip-host-cache' > /etc/mysql/conf.d/docker.cnf

ENTRYPOINT ["docker-entrypoint.sh"]

# EXPOSE 3306
CMD ["mysqld"]
