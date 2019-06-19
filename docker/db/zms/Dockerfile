FROM mariadb:latest

COPY zms_server.sql /docker-entrypoint-initdb.d/

ENTRYPOINT ["docker-entrypoint.sh"]

# EXPOSE 3306
CMD ["mysqld"]
