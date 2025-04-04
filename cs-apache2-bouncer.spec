# RPM Spec file for @PACKAGE_NAME@

Name:      cs-apache2-bouncer
Version:   0.1
Release:   1%{?dist}
Summary:   Apache Crowdsec module
License:   ASL 2.0
Group:     System Environment/Daemons
Source:    https://github.com/crowdsecurity/%{name}/archive/refs/tags/v%{version}.tar.gz
Url:       https://github.com/crowdsecurity/%{name}
BuildRequires: gcc
BuildRequires: apr-util-devel
BuildRequires: apr-devel
BuildRequires: httpd-devel
BuildRequires: automake
Requires: httpd

%if 0%{?suse_version}
%define moduledir %{_libdir}/apache2
%else
%define moduledir %{_libdir}/httpd/modules
%endif

%description
The Apache mod_crowdsec module allows filtering against the crowdsec API.

%prep
%setup -q
%build
aclocal
autoconf
autoheader
automake --add-missing --copy
%configure
%make_build

%install
%make_install

%files
%{moduledir}/mod_crowdsec.so

%changelog
* Fri Apr 04 2025 highpingblorg <omermm.personal@gmail.com> - 0.1-1
- Add changelog
- Add build commands for pre EL10 build
- Fix up build dependencies
- Fix EL7 build requirements
