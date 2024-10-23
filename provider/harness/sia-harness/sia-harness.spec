Name:           sia-harness
Version:        %{PACKAGE_VERSION}
Release:        %{RELEASE}.%{OS_VERSION}
Summary:        Athenz Service Identity Agent (SIA) for Harness Pipelines

Group:          System Environment/Daemons
License:        Apache 2.0
URL:            https://www.athenz.io/
BuildRoot:      %{SOURCEURL0}/rpm/BUILD/%{name}-%{version}-%{release}

%{?systemd_ordering}

%description
%{summary}

%build

%install
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
install -pm 0755 %{BIN_DIR}/siad $RPM_BUILD_ROOT/%{_sbindir}

%files
%{_sbindir}/siad
