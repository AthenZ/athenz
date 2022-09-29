Name:           athenz-ui
Version:        %{PACKAGE_VERSION}
Release:        %{RELEASE}%{?dist}
Summary:        User Interface for Athenz
URL:            https://github.com/AthenZ/athenz
Group:          Installation Script
License:        Apache License 2.0

%description
User Interface for managing Athenz domains, roles, services and policies.


%install
mkdir -p %{buildroot}/opt/%{name}/
mkdir -p %{buildroot}/opt/%{name}/src
mkdir -p %{buildroot}/opt/%{name}/src/components
mkdir -p %{buildroot}/opt/%{name}/src/config
mkdir -p %{buildroot}/opt/%{name}/src/pages
mkdir -p %{buildroot}/opt/%{name}/src/server
mkdir -p %{buildroot}/opt/%{name}/src/redux

cp -r %{SOURCE_DIR}/.next %{buildroot}/opt/%{name}/
cp -r %{SOURCE_DIR}/node_modules %{buildroot}/opt/%{name}/
cp -r %{SOURCE_DIR}/src/components %{buildroot}/opt/%{name}/src/
cp -r %{SOURCE_DIR}/src/config %{buildroot}/opt/%{name}/src/
cp -r %{SOURCE_DIR}/src/pages %{buildroot}/opt/%{name}/src/
cp -r %{SOURCE_DIR}/src/server %{buildroot}/opt/%{name}/src/
cp -r %{SOURCE_DIR}/src/redux %{buildroot}/opt/%{name}/src/
cp -r %{SOURCE_DIR}/src/api.js %{buildroot}/opt/%{name}/src/
cp -r %{SOURCE_DIR}/src/routes.js %{buildroot}/opt/%{name}/src/
cp -r %{SOURCE_DIR}/static %{buildroot}/opt/%{name}/
cp -r %{SOURCE_DIR}/app.js %{buildroot}/opt/%{name}/
cp -r %{SOURCE_DIR}/next.config.js %{buildroot}/opt/%{name}/
cp -r %{SOURCE_DIR}/package.json %{buildroot}/opt/%{name}/
cp -r %{SOURCE_DIR}/pm2.config.js %{buildroot}/opt/%{name}/


%files
%defattr(644, athenz-ui, athenz, 755)
/opt/%{name}/.next
/opt/%{name}/node_modules
/opt/%{name}/src
/opt/%{name}/static
/opt/%{name}/app.js
/opt/%{name}/next.config.js
/opt/%{name}/package.json
/opt/%{name}/pm2.config.js
