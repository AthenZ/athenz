build-docker:
	docker build -t rdl-athenz-server -f docker/util/rdl-athenz-server/Dockerfile rdl/rdl-gen-athenz-server
	docker build -t athenz-builder -f docker/util/athenz-builder/Dockerfile .
	docker build -t athenz-zms -f docker/zms/Dockerfile .
	docker build -t athenz-zts -f docker/zts/Dockerfile .
	docker build -t athenz-ui -f docker/ui/Dockerfile ui
	docker build -t athenz-zms-db -f docker/db/zms/Dockerfile servers/zms/schema
	docker build -t athenz-zts-db -f docker/db/zts/Dockerfile servers/zts/schema

run-docker:
	docker run -d -h localhost -p 4443:4443 -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server -v `pwd`/docker/zms/var:/opt/athenz/zms/var -v `pwd`:/opt/athenz/zms/logs/zms_server --name athenz-zms athenz-zms
	docker run -d -h localhost -p 8443:8443 -v `pwd`/docker/zts/conf:/opt/athenz/zts/conf/zts_server -v `pwd`/docker/zts/var:/opt/athenz/zts/var -v `pwd`:/opt/athenz/zts/logs/zts_server --name athenz-zts athenz-zts
	docker run -d -h localhost -p 9443:9443 -v `pwd`/docker/ui/keys:/opt/athenz/ui/keys --name athenz-ui athenz-ui
	docker run -d -h localhost -p 3306:3306 -e MYSQL_ROOT_PASSWORD=mariadb --name athenz-zms-db athenz-zms-db 
	docker run -d -h localhost -p 3307:3306 -e MYSQL_ROOT_PASSWORD=mariadb --name athenz-zts-db athenz-zts-db 

run-zms-extra-jars:
	docker run -d -h localhost -p 4443:4443 -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server -v `pwd`/docker/zms/var:/opt/athenz/zms/var -v `pwd`:/opt/athenz/zms/logs/zms_server --name athenz-zms -e USER_CLASSPATH='lib/usr/jars/*' -v `pwd`/docker/zms/jars:/opt/athenz/zms/lib/usr/jars athenz-zms
run-zms-custom-cmd:
	docker run -d -h localhost -p 4443:4443 -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server -v `pwd`/docker/zms/var:/opt/athenz/zms/var -v `pwd`:/opt/athenz/zms/logs/zms_server --name athenz-zms athenz-zms -classpath "/path/to/all/jars"
