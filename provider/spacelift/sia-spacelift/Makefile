SCRIPT:=sia.py

all: lint test

lint:
	@echo "Checking syntax..."
	python3 -m py_compile $(SCRIPT)

test:
	@echo "Running tests..."
	python3 -m pytest -v sia_test.py

clean:
	rm -rf __pycache__ .pytest_cache *.pyc

ubuntu:
	sed -i.bak s/SIA_PACKAGE_VERSION/$(PACKAGE_VERSION)/g debian/sia/DEBIAN/control
	mkdir -p debian/sia/usr/local/bin/
	cp -fp $(SCRIPT) debian/sia/usr/local/bin/sia
	chmod +x debian/sia/usr/local/bin/sia
	mkdir -p debian/pkg
	cd debian && dpkg-deb --build sia pkg
