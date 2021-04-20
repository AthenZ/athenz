Name:           sia-eks
Version:        %{PACKAGE_VERSION}
Release:        %{RELEASE}.el%{CENTOS_VERSION}
Summary:        Athenz Service Identity Agent (SIA) for AWS EKS

Group:          System Environment/Daemons
License:        Apache 2.0
URL:            https://www.athenz.io/
Requires:       openssh-server
BuildRoot:      %{SOURCEURL0}/rpm/BUILD/%{name}-%{version}-%{release}

%{?systemd_ordering}

%description
%{summary}

%build

%pre
# Clean up versions previously installed in /etc/sia.
rm -f /etc/sia/siad
getent group athenz >/dev/null 2>&1 || groupadd -g 10952 -r athenz

%install
mkdir -p $RPM_BUILD_ROOT/%{_sbindir}
mkdir -p $RPM_BUILD_ROOT/etc/sia/
install -pm 0755 %{BIN_DIR}/siad $RPM_BUILD_ROOT/%{_sbindir}
mkdir -p $RPM_BUILD_ROOT/%{_unitdir}
install -pm 0644 %{SRC_DIR}/build/service/sia.service $RPM_BUILD_ROOT/%{_unitdir}/


%files
%{_sbindir}/siad
%{_unitdir}/sia.service

%post
%systemd_post sia.service
systemctl enable sia > /dev/null 2>&1

%preun
%systemd_preun sia.service

