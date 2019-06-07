build-docker:
	docker build -t rdl-athenz-server -f docker/util/rdl-athenz-server/Dockerfile rdl/rdl-gen-athenz-server
	docker build -t athenz-mvn-base -f docker/util/athenz-mvn-base/Dockerfile .
	docker build -t athenz-builder -f docker/util/athenz-builder/Dockerfile .
	docker build -t athenz-zms-server -f docker/zms/Dockerfile .
	docker build -t athenz-zts-server -f docker/zts/Dockerfile .
	docker build -t athenz-ui -f docker/ui/Dockerfile ui
	docker build -t athenz-zms-db -f docker/db/zms/Dockerfile servers/zms/schema
	docker build -t athenz-zts-db -f docker/db/zts/Dockerfile servers/zts/schema
	docker build -t athenz-zms-cli -f docker/util/zms-cli/Dockerfile .
	docker build -t athenz-cli-util -f docker/util/Dockerfile .

run-docker:
	docker run -d -h localhost \
		--network=host -p 3306 \
		-v `pwd`/docker/db/zms/zms-db.cnf:/etc/mysql/conf.d/zms-db.cnf \
		-e MYSQL_ROOT_PASSWORD=${ZMS_JDBC_PASSWORD} \
		--name athenz-zms-db athenz-zms-db
	docker run -d -h localhost \
		--network=host -p 3307 \
		-v `pwd`/docker/db/zts/zts-db.cnf:/etc/mysql/conf.d/zts-db.cnf \
		-e MYSQL_ROOT_PASSWORD=${ZTS_CERT_JDBC_PASSWORD} \
		--name athenz-zts-db athenz-zts-db
	docker run -d -h localhost \
		--network=host -p 4443 \
		-v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server \
		-v `pwd`/docker/zms/var:/opt/athenz/zms/var \
		-v `pwd`/docker/logs/zms:/opt/athenz/zms/logs/zms_server \
		-e ZMS_JDBC_PASSWORD=${ZMS_JDBC_PASSWORD} \
		-e ZMS_SSL_KEY_STORE_PASSWORD=${ZMS_SSL_KEY_STORE_PASSWORD} \
		--name athenz-zms-server athenz-zms
	docker run -d -h localhost \
		--network=host -p 8443 \
		-v `pwd`/docker/zts/conf:/opt/athenz/zts/conf/zts_server \
		-v `pwd`/docker/zts/var:/opt/athenz/zts/var \
		-v `pwd`/docker/logs/zts:/opt/athenz/zts/logs/zts_server \
		-e ZTS_CERT_JDBC_PASSWORD=${ZTS_CERT_JDBC_PASSWORD} \
		-e ZTS_SELF_SIGNER_PRIVATE_KEY_PASSWORD=${ZTS_SELF_SIGNER_PRIVATE_KEY_PASSWORD} \
		-e ZTS_ZTS_SSL_KEY_STORE_PASSWORD=${ZTS_ZTS_SSL_KEY_STORE_PASSWORD} \
		-e ZTS_ZTS_SSL_TRUST_STORE_PASSWORD=${ZTS_ZTS_SSL_TRUST_STORE_PASSWORD} \
		-e ZTS_SSL_KEY_STORE_PASSWORD=${ZTS_SSL_KEY_STORE_PASSWORD} \
		-e ZTS_SSL_TRUST_STORE_PASSWORD=${ZTS_SSL_TRUST_STORE_PASSWORD} \
		--name athenz-zts-server athenz-zts
	# docker run -d -h localhost \
	# 	--network=host -p 443 \
	# 	-v `pwd`/docker/zts/conf/athenz.conf:/opt/athenz/ui/config/athenz.conf \
	# 	-v `pwd`/docker/ui/keys:/opt/athenz/ui/keys \
	# 	--name athenz-ui athenz-ui

clean-docker:
	docker ps -a | grep athenz- | awk '{print $$1}' | xargs docker stop
	docker ps -a | grep athenz- | awk '{print $$1}' | xargs docker rm

# run-zms-extra-jars:
# 	docker run -d -h localhost -p 4443:4443 -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server -v `pwd`/docker/zms/var:/opt/athenz/zms/var -v `pwd`:/opt/athenz/zms/logs/zms_server --name athenz-zms -e USER_CLASSPATH='lib/usr/jars/*' -v `pwd`/docker/zms/jars:/opt/athenz/zms/lib/usr/jars athenz-zms
# run-zms-custom-cmd:
# 	docker run -d -h localhost -p 4443:4443 -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server -v `pwd`/docker/zms/var:/opt/athenz/zms/var -v `pwd`:/opt/athenz/zms/logs/zms_server --name athenz-zms athenz-zms -classpath "/path/to/all/jars"
