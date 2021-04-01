Name:           sia-eks
Version:        %{PACKAGE_VERSION}
Release:        %{RELEASE}.el%{CENTOS_VERSION}
Summary:        Athenz Service Identity Agent (SIA) for AWS EKS

Group:          System Environment/Daemons
License:        Apache 2.0
URL:            https://www.athenz.io/
Requires:       openssh-server
BuildRoot:      %{SOURCEURL0}/rpm/BUILD/%{name}-%{version}-%{release}

%if 0%{?CENTOS_VERSION} == 7
%{?systemd_ordering}
%endif

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

%if 0%{?CENTOS_VERSION} == 7
mkdir -p $RPM_BUILD_ROOT/%{_unitdir}
install -pm 0644 %{SRC_DIR}/build/service/sia.service $RPM_BUILD_ROOT/%{_unitdir}/
%else
mkdir -p $RPM_BUILD_ROOT/etc/init.d
install -pm 0755 %{SRC_DIR}/build/service/sia.sysv $RPM_BUILD_ROOT/etc/init.d/sia
%endif

%files
%{_sbindir}/siad

%if 0%{?CENTOS_VERSION} == 7
%{_unitdir}/sia.service
%else
/etc/init.d/sia
%endif

%post
%if 0%{?CENTOS_VERSION} == 7
%systemd_post sia.service
systemctl enable sia > /dev/null 2>&1
%else
chkconfig sia on
%endif

%preun
%if 0%{?CENTOS_VERSION} == 7
%systemd_preun sia.service
%else
service sia stop
chkconfig sia off
%endif
