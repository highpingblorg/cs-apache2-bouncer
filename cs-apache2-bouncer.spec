# RPM Spec file for @PACKAGE_NAME@

Name:      cs-apache2-bouncer
Version:   0.1
Release:   1%{?dist}
Summary:   Apache Crowdsec module
License:   ASL 2.0
Group:     System Environment/Daemons
Source:    https://github.com/crowdsecurity/%{name}/archive/refs/tags/v%{version}.tar.gz
Url:       https://github.com/crowdsecurity/%{name}
BuildRequires: gcc, pkgconfig(apr-1), pkgconfig(apr-util-1), (httpd-devel or apache-devel or apache2-devel)
Requires: (httpd or apache or apache2)

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
%configure
%make_build

%install
%make_install

%files
%{moduledir}/mod_crowdsec.so


