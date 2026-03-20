%define _build_id_links none
%define debug_package %{nil}

Summary:          CWorthy Linux Server Console
License:          LGPL
Name:             sysmon
Version:          1.0
Release:          0%{?dist}

URL:              http://www.leaflinux.org/
Source0:          %{name}-%{version}.tar.gz

BuildRequires:    systemd

%description 
The %{name} package contains the CWorthy Linux Server Console.

%prep
%setup -q -n %{name}-%{version}

%build
%{__make} 

%install
[ -n "%{buildroot}" -a "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}
%{__mkdir_p} %{buildroot}%{_sbindir}
%{__mkdir_p} %{buildroot}%{_bindir}
%{__make} \
	DESTDIR=%{buildroot} BINDIR=%{_bindir} \
	install

%pre

%post

%preun

%postun

%files
%defattr(-,root,root)
%{_bindir}/sysmon

%changelog
