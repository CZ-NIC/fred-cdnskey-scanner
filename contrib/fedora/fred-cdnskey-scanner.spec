Name:		fred-cdnskey-scanner
Version:	%{our_version}
Release:	%{?our_release}%{!?our_release:1}%{?dist}
Summary:	FRED - Scanner for CDNSKEY DNS resource records
Group:		Applications/Utils
License:	GPLv3+
URL:		http://fred.nic.cz
Source0:      %{name}-%{version}.tar.gz
BuildRoot:    %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: git, cmake, gcc-c++, libevent-devel, boost-devel, boost-system, openssl-devel libidn2-devel, unbound-devel, check-devel
Requires:  glibc, libstdc++, libevent, boost-system

%description
FRED (Free Registry for Enum and Domain) is free registry system for 
managing domain registrations. This package contains cmdline script for
Automated Keyset Management

%prep
%setup -q

%build
%cmake -DVERSION=%{version} -DCMAKE_INSTALL_PREFIX=/ -DUSE_USR_PREFIX=1 .
%cmake_build

%install
%cmake_install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/usr/bin/cdnskey-scanner
