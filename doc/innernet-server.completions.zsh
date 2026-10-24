#compdef innernet-server

autoload -U is-at-least

_innernet-server() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'-c+[]:CONFIG_DIR:_files' \
'--config-dir=[]:CONFIG_DIR:_files' \
'-d+[]:DATA_DIR:_files' \
'--data-dir=[]:DATA_DIR:_files' \
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]:BACKEND:(kernel userspace)' \
'--mtu=[Specify the desired MTU for your interface (default\: 1280)]:MTU:_default' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_innernet-server_commands" \
"*::: :->innernet-server" \
&& ret=0
    case $state in
    (innernet-server)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:innernet-server-command-$line[1]:"
        case $line[1] in
            (new)
_arguments "${_arguments_options[@]}" : \
'--network-name=[The network name (ex\: evilcorp)]:NETWORK_NAME:_default' \
'--network-cidr=[The network CIDR (ex\: 10.42.0.0/16)]:NETWORK_CIDR:_default' \
'(--auto-external-endpoint)--external-endpoint=[This server'\''s external endpoint (ex\: 100.100.100.100\:51820)]:EXTERNAL_ENDPOINT:_default' \
'--listen-port=[Port to listen on (for the WireGuard interface)]:LISTEN_PORT:_default' \
'--quic-port=[UDP port of the TLS API, over QUIC at the server'\''s internal address (default\: a free port, which an interactive run offers to change)]:QUIC_PORT:_default' \
'--auto-external-endpoint[Auto-resolve external endpoint]' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(uninstall)
_arguments "${_arguments_options[@]}" : \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(serve)
_arguments "${_arguments_options[@]}" : \
'--backend=[Specify a WireGuard backend to use. If not set, innernet will auto-select based on availability]:BACKEND:(kernel userspace)' \
'--mtu=[Specify the desired MTU for your interface (default\: 1280)]:MTU:_default' \
'--hosts-path=[Ignored\: innernet no longer writes a hosts file. Accepted so that existing invocations keep working]:HOSTS_PATH:_files' \
'--host-suffix=[Use a different suffix for the hostnames of peers that the DNS server answers for, than '\''INTERFACE.wg'\'', ex. --host-suffix '\''evilnet'\'' names peers\: PEER.evilnet]:HOST_SUFFIX:_default' \
'--no-routing[Whether the routing should be done by innernet or is done by an external tool like e.g. babeld]' \
'--no-write-hosts[Ignored\: innernet no longer writes a hosts file. Accepted so that existing invocations keep working]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(add-peer)
_arguments "${_arguments_options[@]}" : \
'--name=[Name of new peer]:NAME:_default' \
'(--auto-ip)--ip=[Specify desired IP of new peer (within parent CIDR), which the peer is offered as a /32 or /128 delegation]:IP:_default' \
'(--ip --auto-ip)--delegation=[Offer the new peer this prefix of its CIDR as its delegation, rather than a single IP (eg. '\''10.42.5.16/28'\'')]:DELEGATION:_default' \
'--cidr=[Name of CIDR to add new peer under]:CIDR:_default' \
'--admin=[Make new peer an admin?]:ADMIN:(true false)' \
'--save-config=[Save the config to the given location]:SAVE_CONFIG:_default' \
'--invite-expires=[Invite expiration period (eg. '\''30d'\'', '\''7w'\'', '\''2h'\'', '\''60m'\'', '\''1000s'\'')]:INVITE_EXPIRES:_default' \
'--auto-ip[Auto-assign the peer the first available IP within the CIDR]' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(disable-peer)
_arguments "${_arguments_options[@]}" : \
'--name=[Name of peer to enable/disable]:NAME:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(enable-peer)
_arguments "${_arguments_options[@]}" : \
'--name=[Name of peer to enable/disable]:NAME:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(add-delegation)
_arguments "${_arguments_options[@]}" : \
'--name=[Name of the peer whose delegations change]:NAME:_default' \
'--prefix=[The prefix to delegate, withdraw or mark (eg. '\''10.42.5.16/28'\'', or '\''10.42.5.9/32'\'' for a single address)]:PREFIX:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':interface:_default' \
&& ret=0
;;
(withdraw-delegation)
_arguments "${_arguments_options[@]}" : \
'--name=[Name of the peer whose delegations change]:NAME:_default' \
'--prefix=[The prefix to delegate, withdraw or mark (eg. '\''10.42.5.16/28'\'', or '\''10.42.5.9/32'\'' for a single address)]:PREFIX:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':interface:_default' \
&& ret=0
;;
(reclaim-delegation)
_arguments "${_arguments_options[@]}" : \
'--name=[Name of the peer whose delegations change]:NAME:_default' \
'--prefix=[The prefix to delegate, withdraw or mark (eg. '\''10.42.5.16/28'\'', or '\''10.42.5.9/32'\'' for a single address)]:PREFIX:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':interface:_default' \
&& ret=0
;;
(rename-peer)
_arguments "${_arguments_options[@]}" : \
'--name=[Name of peer to rename]:NAME:_default' \
'--new-name=[The new name of the peer]:NEW_NAME:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(add-cidr)
_arguments "${_arguments_options[@]}" : \
'--name=[The CIDR name (eg. '\''engineers'\'')]:NAME:_default' \
'--cidr=[The CIDR network (eg. '\''10.42.5.0/24'\'')]:CIDR:_default' \
'--parent=[The CIDR parent name]:PARENT:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(rename-cidr)
_arguments "${_arguments_options[@]}" : \
'--name=[Name of CIDR to rename]:NAME:_default' \
'--new-name=[The new name of the CIDR]:NEW_NAME:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(delete-cidr)
_arguments "${_arguments_options[@]}" : \
'--name=[The CIDR name (eg. '\''engineers'\'')]:NAME:_default' \
'--yes[Bypass confirmation]' \
'-h[Print help]' \
'--help[Print help]' \
':interface:_default' \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
'--help[Print help]' \
':shell:(bash elvish fish powershell zsh)' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_innernet-server__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:innernet-server-help-command-$line[1]:"
        case $line[1] in
            (new)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(uninstall)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(serve)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(add-peer)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(disable-peer)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enable-peer)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(add-delegation)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(withdraw-delegation)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(reclaim-delegation)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rename-peer)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(add-cidr)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rename-cidr)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(delete-cidr)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_innernet-server_commands] )) ||
_innernet-server_commands() {
    local commands; commands=(
'new:Create a new network' \
'uninstall:Permanently uninstall a created network, rendering it unusable. Use with care' \
'serve:Serve the coordinating server for an existing network' \
'add-peer:Add a peer to an existing network' \
'disable-peer:Disable an enabled peer' \
'enable-peer:Enable a disabled peer' \
'add-delegation:Delegate a prefix of a peer'\''s CIDR to the peer' \
'withdraw-delegation:Withdraw a delegation from a peer' \
'reclaim-delegation:Mark a delegation of a peer to be reclaimed' \
'rename-peer:Rename an existing peer' \
'add-cidr:Add a new CIDR to an existing network' \
'rename-cidr:Rename an existing CIDR' \
'delete-cidr:Delete a CIDR' \
'completions:Generate shell completion scripts' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'innernet-server commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__add-cidr_commands] )) ||
_innernet-server__subcmd__add-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server add-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__add-delegation_commands] )) ||
_innernet-server__subcmd__add-delegation_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server add-delegation commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__add-peer_commands] )) ||
_innernet-server__subcmd__add-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server add-peer commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__completions_commands] )) ||
_innernet-server__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server completions commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__delete-cidr_commands] )) ||
_innernet-server__subcmd__delete-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server delete-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__disable-peer_commands] )) ||
_innernet-server__subcmd__disable-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server disable-peer commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__enable-peer_commands] )) ||
_innernet-server__subcmd__enable-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server enable-peer commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help_commands] )) ||
_innernet-server__subcmd__help_commands() {
    local commands; commands=(
'new:Create a new network' \
'uninstall:Permanently uninstall a created network, rendering it unusable. Use with care' \
'serve:Serve the coordinating server for an existing network' \
'add-peer:Add a peer to an existing network' \
'disable-peer:Disable an enabled peer' \
'enable-peer:Enable a disabled peer' \
'add-delegation:Delegate a prefix of a peer'\''s CIDR to the peer' \
'withdraw-delegation:Withdraw a delegation from a peer' \
'reclaim-delegation:Mark a delegation of a peer to be reclaimed' \
'rename-peer:Rename an existing peer' \
'add-cidr:Add a new CIDR to an existing network' \
'rename-cidr:Rename an existing CIDR' \
'delete-cidr:Delete a CIDR' \
'completions:Generate shell completion scripts' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'innernet-server help commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__add-cidr_commands] )) ||
_innernet-server__subcmd__help__subcmd__add-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help add-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__add-delegation_commands] )) ||
_innernet-server__subcmd__help__subcmd__add-delegation_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help add-delegation commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__add-peer_commands] )) ||
_innernet-server__subcmd__help__subcmd__add-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help add-peer commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__completions_commands] )) ||
_innernet-server__subcmd__help__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help completions commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__delete-cidr_commands] )) ||
_innernet-server__subcmd__help__subcmd__delete-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help delete-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__disable-peer_commands] )) ||
_innernet-server__subcmd__help__subcmd__disable-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help disable-peer commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__enable-peer_commands] )) ||
_innernet-server__subcmd__help__subcmd__enable-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help enable-peer commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__help_commands] )) ||
_innernet-server__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help help commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__new_commands] )) ||
_innernet-server__subcmd__help__subcmd__new_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help new commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__reclaim-delegation_commands] )) ||
_innernet-server__subcmd__help__subcmd__reclaim-delegation_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help reclaim-delegation commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__rename-cidr_commands] )) ||
_innernet-server__subcmd__help__subcmd__rename-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help rename-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__rename-peer_commands] )) ||
_innernet-server__subcmd__help__subcmd__rename-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help rename-peer commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__serve_commands] )) ||
_innernet-server__subcmd__help__subcmd__serve_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help serve commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__uninstall_commands] )) ||
_innernet-server__subcmd__help__subcmd__uninstall_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help uninstall commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__help__subcmd__withdraw-delegation_commands] )) ||
_innernet-server__subcmd__help__subcmd__withdraw-delegation_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server help withdraw-delegation commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__new_commands] )) ||
_innernet-server__subcmd__new_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server new commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__reclaim-delegation_commands] )) ||
_innernet-server__subcmd__reclaim-delegation_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server reclaim-delegation commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__rename-cidr_commands] )) ||
_innernet-server__subcmd__rename-cidr_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server rename-cidr commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__rename-peer_commands] )) ||
_innernet-server__subcmd__rename-peer_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server rename-peer commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__serve_commands] )) ||
_innernet-server__subcmd__serve_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server serve commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__uninstall_commands] )) ||
_innernet-server__subcmd__uninstall_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server uninstall commands' commands "$@"
}
(( $+functions[_innernet-server__subcmd__withdraw-delegation_commands] )) ||
_innernet-server__subcmd__withdraw-delegation_commands() {
    local commands; commands=()
    _describe -t commands 'innernet-server withdraw-delegation commands' commands "$@"
}

if [ "$funcstack[1]" = "_innernet-server" ]; then
    _innernet-server "$@"
else
    compdef _innernet-server innernet-server
fi
