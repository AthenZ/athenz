Name:           sia-run
Version:        %{PACKAGE_VERSION}
Release:        %{RELEASE}.el%{CENTOS_VERSION}
Summary:        Athenz Service Identity Agent (SIA) for GCP Run

Group:          System Environment/Daemons
License:        Apache 2.0
URL:            https://www.athenz.io/
BuildRoot:      %{SOURCEURL0}/rpm/BUILD/%{name}-%{version}-%{release}

%{?systemd_ordering}

%description
%{summary}

%build

%pre
getent group athenz >/dev/null 2>&1 || groupadd -g 10952 -r athenz

%install
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
mkdir -p $RPM_BUILD_ROOT/etc/sia/
install -pm 0755 %{BIN_DIR}/siad $RPM_BUILD_ROOT/%{_sbindir}

%files
%{_sbindir}/siad
