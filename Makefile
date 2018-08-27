build-docker:
	docker build -t rdl-athenz-server -f docker/util/rdl-athenz-server/Dockerfile rdl/rdl-gen-athenz-server
	docker build -t athenz-builder -f docker/util/athenz-builder/Dockerfile .
	docker build -t athenz-zms -f docker/zms/Dockerfile .
	#docker build -t athenz-zts -f docker/zts/Dockerfile .
	#docker build -t athenz-ui -f docker/ui/Dockerfile .
