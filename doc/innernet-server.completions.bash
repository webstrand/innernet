_innernet-server() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="innernet__server"
                ;;
            innernet__server,add-cidr)
                cmd="innernet__server__subcmd__add__subcmd__cidr"
                ;;
            innernet__server,add-delegation)
                cmd="innernet__server__subcmd__add__subcmd__delegation"
                ;;
            innernet__server,add-peer)
                cmd="innernet__server__subcmd__add__subcmd__peer"
                ;;
            innernet__server,completions)
                cmd="innernet__server__subcmd__completions"
                ;;
            innernet__server,delete-cidr)
                cmd="innernet__server__subcmd__delete__subcmd__cidr"
                ;;
            innernet__server,disable-peer)
                cmd="innernet__server__subcmd__disable__subcmd__peer"
                ;;
            innernet__server,enable-peer)
                cmd="innernet__server__subcmd__enable__subcmd__peer"
                ;;
            innernet__server,help)
                cmd="innernet__server__subcmd__help"
                ;;
            innernet__server,new)
                cmd="innernet__server__subcmd__new"
                ;;
            innernet__server,reclaim-delegation)
                cmd="innernet__server__subcmd__reclaim__subcmd__delegation"
                ;;
            innernet__server,rename-cidr)
                cmd="innernet__server__subcmd__rename__subcmd__cidr"
                ;;
            innernet__server,rename-peer)
                cmd="innernet__server__subcmd__rename__subcmd__peer"
                ;;
            innernet__server,serve)
                cmd="innernet__server__subcmd__serve"
                ;;
            innernet__server,uninstall)
                cmd="innernet__server__subcmd__uninstall"
                ;;
            innernet__server,withdraw-delegation)
                cmd="innernet__server__subcmd__withdraw__subcmd__delegation"
                ;;
            innernet__server__subcmd__help,add-cidr)
                cmd="innernet__server__subcmd__help__subcmd__add__subcmd__cidr"
                ;;
            innernet__server__subcmd__help,add-delegation)
                cmd="innernet__server__subcmd__help__subcmd__add__subcmd__delegation"
                ;;
            innernet__server__subcmd__help,add-peer)
                cmd="innernet__server__subcmd__help__subcmd__add__subcmd__peer"
                ;;
            innernet__server__subcmd__help,completions)
                cmd="innernet__server__subcmd__help__subcmd__completions"
                ;;
            innernet__server__subcmd__help,delete-cidr)
                cmd="innernet__server__subcmd__help__subcmd__delete__subcmd__cidr"
                ;;
            innernet__server__subcmd__help,disable-peer)
                cmd="innernet__server__subcmd__help__subcmd__disable__subcmd__peer"
                ;;
            innernet__server__subcmd__help,enable-peer)
                cmd="innernet__server__subcmd__help__subcmd__enable__subcmd__peer"
                ;;
            innernet__server__subcmd__help,help)
                cmd="innernet__server__subcmd__help__subcmd__help"
                ;;
            innernet__server__subcmd__help,new)
                cmd="innernet__server__subcmd__help__subcmd__new"
                ;;
            innernet__server__subcmd__help,reclaim-delegation)
                cmd="innernet__server__subcmd__help__subcmd__reclaim__subcmd__delegation"
                ;;
            innernet__server__subcmd__help,rename-cidr)
                cmd="innernet__server__subcmd__help__subcmd__rename__subcmd__cidr"
                ;;
            innernet__server__subcmd__help,rename-peer)
                cmd="innernet__server__subcmd__help__subcmd__rename__subcmd__peer"
                ;;
            innernet__server__subcmd__help,serve)
                cmd="innernet__server__subcmd__help__subcmd__serve"
                ;;
            innernet__server__subcmd__help,uninstall)
                cmd="innernet__server__subcmd__help__subcmd__uninstall"
                ;;
            innernet__server__subcmd__help,withdraw-delegation)
                cmd="innernet__server__subcmd__help__subcmd__withdraw__subcmd__delegation"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        innernet__server)
            opts="-c -d -h -V --config-dir --data-dir --no-routing --backend --mtu --help --version new uninstall serve add-peer disable-peer enable-peer add-delegation withdraw-delegation reclaim-delegation rename-peer add-cidr rename-cidr delete-cidr completions help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --data-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -d)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --backend)
                    COMPREPLY=($(compgen -W "kernel userspace" -- "${cur}"))
                    return 0
                    ;;
                --mtu)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__add__subcmd__cidr)
            opts="-h --name --cidr --parent --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cidr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --parent)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__add__subcmd__delegation)
            opts="-h --name --prefix --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__add__subcmd__peer)
            opts="-h --name --ip --auto-ip --delegation --cidr --admin --yes --save-config --invite-expires --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ip)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --delegation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cidr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --admin)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --save-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --invite-expires)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__completions)
            opts="-h --help bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__delete__subcmd__cidr)
            opts="-h --name --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__disable__subcmd__peer)
            opts="-h --name --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__enable__subcmd__peer)
            opts="-h --name --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help)
            opts="new uninstall serve add-peer disable-peer enable-peer add-delegation withdraw-delegation reclaim-delegation rename-peer add-cidr rename-cidr delete-cidr completions help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__add__subcmd__cidr)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__add__subcmd__delegation)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__add__subcmd__peer)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__delete__subcmd__cidr)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__disable__subcmd__peer)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__enable__subcmd__peer)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__new)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__reclaim__subcmd__delegation)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__rename__subcmd__cidr)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__rename__subcmd__peer)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__serve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__uninstall)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__help__subcmd__withdraw__subcmd__delegation)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__new)
            opts="-h --network-name --network-cidr --external-endpoint --auto-external-endpoint --listen-port --quic-port --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --network-name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --network-cidr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --external-endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --listen-port)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --quic-port)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__reclaim__subcmd__delegation)
            opts="-h --name --prefix --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__rename__subcmd__cidr)
            opts="-h --name --new-name --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__rename__subcmd__peer)
            opts="-h --name --new-name --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__serve)
            opts="-h --no-routing --backend --mtu --hosts-path --no-write-hosts --host-suffix --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --backend)
                    COMPREPLY=($(compgen -W "kernel userspace" -- "${cur}"))
                    return 0
                    ;;
                --mtu)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --hosts-path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-suffix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__uninstall)
            opts="-h --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        innernet__subcmd__server__subcmd__withdraw__subcmd__delegation)
            opts="-h --name --prefix --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _innernet-server -o nosort -o bashdefault -o default innernet-server
else
    complete -F _innernet-server -o bashdefault -o default innernet-server
fi
