Name:		cdnskey-scanner
Version:	%{our_version}
Release:	%{?our_release}%{!?our_release:1}%{?dist}
Summary:	FRED - Scanner for CDNSKEY DNS resource records
Group:		Applications/Utils
License:	GPL
URL:		http://fred.nic.cz
Source0:      %{name}-%{version}.tar.gz
BuildRoot:    %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  git, gcc-c++, getdns-devel >= 1.2.1, libevent-devel, boost-devel, boost-system
%if 0%{?centos}
BuildRequires: centos-release-scl, devtoolset-7, devtoolset-7-build, llvm-toolset-7-cmake, llvm-toolset-7-build
%else
BuildRequires: cmake
%endif
Requires:  glibc, libstdc++, getdns >= 1.2.1, libevent, boost-system

%description
FRED (Free Registry for Enum and Domain) is free registry system for 
managing domain registrations. This package contains cmdline script for
Automated Keyset Management

%prep
%setup -q

%build
%if 0%{?centos}
%{?scl:scl enable devtoolset-7 llvm-toolset-7 - << \EOF}
%global __cmake /opt/rh/llvm-toolset-7/root/usr/bin/cmake
%endif
%cmake -DVERSION=%{version} .
%make_build
%if 0%{?centos}
%{?scl:EOF}
%endif

%install
%make_install

%check
%if 0%{?centos}
%{?scl:scl enable llvm-toolset-7 - << \EOF}
%endif
ctest -V %{?_smp_mflags}
%if 0%{?centos}
%{?scl:EOF}
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/usr/bin/cdnskey-scanner
