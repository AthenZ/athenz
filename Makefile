build-docker:
	docker build -t rdl-athenz-server -f docker/util/rdl-athenz-server/Dockerfile rdl/rdl-gen-athenz-server
	docker build -t athenz-builder -f docker/util/athenz-builder/Dockerfile .
	docker build -t athenz-zms -f docker/zms/Dockerfile .
	docker build -t athenz-zts -f docker/zts/Dockerfile .
	#docker build -t athenz-ui -f docker/ui/Dockerfile .

run-docker:
	docker run --rm -h localhost -p 4443:4443 -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server -v `pwd`/docker/zms/var:/opt/athenz/zms/var -v `pwd`:/opt/athenz/zms/logs/zms_server --name athenz-zms athenz-zms
	docker run --rm -h localhost -p 8443:8443 -v `pwd`/docker/zts/conf:/opt/athenz/zts/conf/zts_server -v `pwd`/docker/zts/var:/opt/athenz/zts/var -v `pwd`:/opt/athenz/zts/logs/zts_server --name athenz-zts athenz-zts
