# Packages a client that cargo has already built; rpm/assemble.sh supplies %%{repo},
# %%{bin_dir} and %%{pkg_version}. Nothing here compiles anything.

%global debug_package %{nil}

Name:       innernet
Version:    %{pkg_version}
Release:    1
Summary:    A client to manage innernet network interfaces
License:    MIT
URL:        https://github.com/tonarino/innernet

%description
innernet client binary for fetching peer information and conducting admin tasks such as adding a
new peer.

%install
install -Dm755 %{bin_dir}/innernet %{buildroot}%{_bindir}/innernet
install -Dm644 %{repo}/doc/innernet.8 %{buildroot}%{_mandir}/man8/innernet.8
install -Dm644 %{repo}/client/innernet@.service %{buildroot}%{_unitdir}/innernet@.service
install -Dm644 %{repo}/client/innernet.target %{buildroot}%{_unitdir}/innernet.target
install -Dm644 %{repo}/doc/innernet.completions.bash %{buildroot}%{_datadir}/bash-completion/completions/innernet
install -Dm644 %{repo}/doc/innernet.completions.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/innernet.fish
install -Dm644 %{repo}/doc/innernet.completions.zsh %{buildroot}%{_datadir}/zsh/site-functions/_innernet

%files
%{_bindir}/innernet
%{_mandir}/man8/innernet.8*
%{_unitdir}/innernet@.service
%{_unitdir}/innernet.target
%{_datadir}/bash-completion/completions/innernet
%dir %{_datadir}/fish
%dir %{_datadir}/fish/vendor_completions.d
%{_datadir}/fish/vendor_completions.d/innernet.fish
%dir %{_datadir}/zsh
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_innernet
