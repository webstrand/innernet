# Packages a server that cargo has already built; rpm/assemble.sh supplies %%{repo},
# %%{bin_dir} and %%{pkg_version}. Nothing here compiles anything.

%global debug_package %{nil}

Name:       innernet-server
Version:    %{pkg_version}
Release:    1
Summary:    A server to coordinate innernet networks
License:    MIT
URL:        https://github.com/tonarino/innernet
Recommends: wireguard-tools

%description
innernet server binary for coordinating innernet networks.

%install
install -Dm755 %{bin_dir}/innernet-server %{buildroot}%{_bindir}/innernet-server
install -Dm644 %{repo}/doc/innernet-server.8 %{buildroot}%{_mandir}/man8/innernet-server.8
install -Dm644 %{repo}/server/innernet-server@.service %{buildroot}%{_unitdir}/innernet-server@.service
install -Dm644 %{repo}/doc/innernet-server.completions.bash %{buildroot}%{_datadir}/bash-completion/completions/innernet-server
install -Dm644 %{repo}/doc/innernet-server.completions.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/innernet-server.fish
install -Dm644 %{repo}/doc/innernet-server.completions.zsh %{buildroot}%{_datadir}/zsh/site-functions/_innernet-server

%files
%{_bindir}/innernet-server
%{_mandir}/man8/innernet-server.8*
%{_unitdir}/innernet-server@.service
%{_datadir}/bash-completion/completions/innernet-server
%dir %{_datadir}/fish
%dir %{_datadir}/fish/vendor_completions.d
%{_datadir}/fish/vendor_completions.d/innernet-server.fish
%dir %{_datadir}/zsh
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_innernet-server
