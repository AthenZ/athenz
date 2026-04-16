SCRIPT:=sia.py
VENV:=.venv
PYTHON:=$(VENV)/bin/python3
PIP:=$(VENV)/bin/pip

all: lint test

$(VENV):
	python3 -m venv $(VENV)
	$(PIP) install --quiet pytest cryptography PyJWT requests

lint: $(VENV)
	@echo "Checking syntax..."
	$(PYTHON) -m py_compile $(SCRIPT)

test: $(VENV)
	@echo "Running tests..."
	$(PYTHON) -m pytest -v sia_test.py

clean:
	rm -rf __pycache__ .pytest_cache *.pyc $(VENV)

ubuntu:
	sed -i.bak s/SIA_PACKAGE_VERSION/$(PACKAGE_VERSION)/g debian/sia/DEBIAN/control
	mkdir -p debian/sia/usr/local/bin/
	cp -fp $(SCRIPT) debian/sia/usr/local/bin/sia
	chmod +x debian/sia/usr/local/bin/sia
	mkdir -p debian/pkg
	cd debian && dpkg-deb --build sia pkg
