GOPKGNAME:=github.com/AthenZ/athenz/provider/aws/sia-ec2
export GOPATH ?= /tmp/go
export GOPRIVATE=github.com

FMT_LOG=/tmp/fmt.log

build: get build_mac build_linux test

mac:   get build_mac test

linux: get build_linux test

build_mac:
	@echo "Building mac client..."
	GOOS=darwin go install -ldflags -v $(GOPKGNAME)/...

build_linux:
	@echo "Building linux client..."
	GOOS=linux go install -ldflags -v $(GOPKGNAME)/...

get:
	@echo "Getting dependencies..."
	go get -t -d -tags testing $(GOPKGNAME)/...

vet:
	go vet $(GOPKGNAME)/...

fmt:
	gofmt -d . >$(FMT_LOG)
	@if [ -s $(FMT_LOG) ]; then echo gofmt FAIL; cat $(FMT_LOG); false; fi

test: vet fmt
	go test -v $(GOPKGNAME)/...

clean:
	go clean -i -x $(GOPKGNAME)/...

ubuntu:
	sed -i.bak s/SIA_PACKAGE_VERSION/$(PACKAGE_VERSION)/g debian/sia/DEBIAN/control
	mkdir -p debian/sia/usr/lib/systemd/system/
	cp -fp $(GOPATH)/src/$(GOPKGNAME)/build/service/sia.service debian/sia/usr/lib/systemd/system/
	mkdir -p debian/sia/usr/sbin/
	cp -fp $(GOPATH)/bin/siad debian/sia/usr/sbin/
	cp debian/ubuntu/postinst debian/sia/DEBIAN/
	cp debian/ubuntu/preinst debian/sia/DEBIAN/
	mkdir -p debian/pkg
	cd debian && dpkg-deb --build sia pkg