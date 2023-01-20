GOPKGNAME:=github.com/AthenZ/athenz/provider/aws/sia-ec2
export GOPATH ?= /tmp/go
export GOPRIVATE=github.com

FMT_LOG=/tmp/fmt.log

BUILD_VERSION:=development

all: build_darwin build_linux build_windows test

build: get all

mac:   get build_darwin test

linux: get build_linux test

build_darwin:
	@echo "Building darwin client with $(BUILD_VERSION)"
	GOOS=darwin go install -ldflags "-X main.Version=$(BUILD_VERSION)" -v $(GOPKGNAME)/...

build_linux:
	@echo "Building linux client with $(BUILD_VERSION)"
	GOOS=linux go install -ldflags "-X main.Version=$(BUILD_VERSION)" -v $(GOPKGNAME)/...

build_windows:
	@echo "Building windows client with $(BUILD_VERSION)"
	GOOS=windows go install -ldflags "-X main.Version=$(BUILD_VERSION)" -v $(GOPKGNAME)/...

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
