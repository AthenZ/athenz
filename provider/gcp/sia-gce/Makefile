GOPKGNAME:=github.com/AthenZ/athenz/provider/gcp/sia-gce
export GOPATH ?= /tmp/go
export GOPRIVATE=github.com

FMT_LOG=/tmp/fmt.log

BUILD_VERSION:=development
CENTOS_VERSION:=7

all: build_darwin build_linux test

local: build test

darwin: build_darwin test

linux: build_linux test

build: build_darwin build_linux

build_darwin:
	@echo "Building darwin arm64 client with $(BUILD_VERSION)"
	GOOS=darwin GOARCH=arm64 go install -ldflags "-X main.Version=$(BUILD_VERSION)" -v $(GOPKGNAME)/...
	@echo "Building darwin amd64 client with $(BUILD_VERSION)"
	GOOS=darwin GOARCH=amd64 go install -ldflags "-X main.Version=$(BUILD_VERSION)" -v $(GOPKGNAME)/...

build_linux:
	@echo "Building linux arm64 client with $(BUILD_VERSION)"
	GOOS=linux GOARCH=arm64 go install -ldflags "-X main.Version=$(BUILD_VERSION)" -v $(GOPKGNAME)/...
	@echo "Building linux client with $(BUILD_VERSION)"
	GOOS=linux GOARCH=amd64 go install -ldflags "-X main.Version=$(BUILD_VERSION)" -v $(GOPKGNAME)/...

vet:
	go vet $(GOPKGNAME)/...

fmt:
	gofmt -d . >$(FMT_LOG)
	@if [ -s $(FMT_LOG) ]; then echo gofmt FAIL; cat $(FMT_LOG); false; fi

test: vet fmt
	go test -v $(GOPKGNAME)/...

clean:
	go clean -i -x $(GOPKGNAME)/...

custom.clean.post:
	rm -rf $(GOPATH)/bin/{linux_amd64,linux_arm64}/{metamock,siad}


RPM_DIR := $(shell pwd)/rpm
RPM_VARS :=
RPM_VARS += --define 'BIN_DIR $(GOPATH)/bin'
RPM_VARS += --define 'PACKAGE_VERSION $(BUILD_VERSION)'
RPM_VARS += --define 'RELEASE 1'
RPM_VARS += --define 'CENTOS_VERSION $(CENTOS_VERSION)'
RPM_VARS += --define '_topdir $(RPM_DIR)'

package:
	echo "rpmbuild $(RPM_VARS) -bb sia-gce.spec"
	find $(GOPATH)/bin
	echo "siad version"
	$(GOPATH)/bin/siad -version
	rpmbuild $(RPM_VARS) -bb sia-gce.spec

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
