_innernet() {
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
                cmd="innernet"
                ;;
            innernet,add-association)
                cmd="innernet__subcmd__add__subcmd__association"
                ;;
            innernet,add-cidr)
                cmd="innernet__subcmd__add__subcmd__cidr"
                ;;
            innernet,add-peer)
                cmd="innernet__subcmd__add__subcmd__peer"
                ;;
            innernet,completions)
                cmd="innernet__subcmd__completions"
                ;;
            innernet,delete-association)
                cmd="innernet__subcmd__delete__subcmd__association"
                ;;
            innernet,delete-cidr)
                cmd="innernet__subcmd__delete__subcmd__cidr"
                ;;
            innernet,delete-peer)
                cmd="innernet__subcmd__delete__subcmd__peer"
                ;;
            innernet,disable-peer)
                cmd="innernet__subcmd__disable__subcmd__peer"
                ;;
            innernet,down)
                cmd="innernet__subcmd__down"
                ;;
            innernet,enable-peer)
                cmd="innernet__subcmd__enable__subcmd__peer"
                ;;
            innernet,fetch)
                cmd="innernet__subcmd__fetch"
                ;;
            innernet,forget-peer)
                cmd="innernet__subcmd__forget__subcmd__peer"
                ;;
            innernet,help)
                cmd="innernet__subcmd__help"
                ;;
            innernet,install)
                cmd="innernet__subcmd__install"
                ;;
            innernet,list-associations)
                cmd="innernet__subcmd__list__subcmd__associations"
                ;;
            innernet,list-cidrs)
                cmd="innernet__subcmd__list__subcmd__cidrs"
                ;;
            innernet,override-endpoint)
                cmd="innernet__subcmd__override__subcmd__endpoint"
                ;;
            innernet,override-peer-endpoint)
                cmd="innernet__subcmd__override__subcmd__peer__subcmd__endpoint"
                ;;
            innernet,rename-cidr)
                cmd="innernet__subcmd__rename__subcmd__cidr"
                ;;
            innernet,rename-peer)
                cmd="innernet__subcmd__rename__subcmd__peer"
                ;;
            innernet,set-listen-port)
                cmd="innernet__subcmd__set__subcmd__listen__subcmd__port"
                ;;
            innernet,show)
                cmd="innernet__subcmd__show"
                ;;
            innernet,uninstall)
                cmd="innernet__subcmd__uninstall"
                ;;
            innernet,up)
                cmd="innernet__subcmd__up"
                ;;
            innernet__subcmd__help,add-association)
                cmd="innernet__subcmd__help__subcmd__add__subcmd__association"
                ;;
            innernet__subcmd__help,add-cidr)
                cmd="innernet__subcmd__help__subcmd__add__subcmd__cidr"
                ;;
            innernet__subcmd__help,add-peer)
                cmd="innernet__subcmd__help__subcmd__add__subcmd__peer"
                ;;
            innernet__subcmd__help,completions)
                cmd="innernet__subcmd__help__subcmd__completions"
                ;;
            innernet__subcmd__help,delete-association)
                cmd="innernet__subcmd__help__subcmd__delete__subcmd__association"
                ;;
            innernet__subcmd__help,delete-cidr)
                cmd="innernet__subcmd__help__subcmd__delete__subcmd__cidr"
                ;;
            innernet__subcmd__help,delete-peer)
                cmd="innernet__subcmd__help__subcmd__delete__subcmd__peer"
                ;;
            innernet__subcmd__help,disable-peer)
                cmd="innernet__subcmd__help__subcmd__disable__subcmd__peer"
                ;;
            innernet__subcmd__help,down)
                cmd="innernet__subcmd__help__subcmd__down"
                ;;
            innernet__subcmd__help,enable-peer)
                cmd="innernet__subcmd__help__subcmd__enable__subcmd__peer"
                ;;
            innernet__subcmd__help,fetch)
                cmd="innernet__subcmd__help__subcmd__fetch"
                ;;
            innernet__subcmd__help,forget-peer)
                cmd="innernet__subcmd__help__subcmd__forget__subcmd__peer"
                ;;
            innernet__subcmd__help,help)
                cmd="innernet__subcmd__help__subcmd__help"
                ;;
            innernet__subcmd__help,install)
                cmd="innernet__subcmd__help__subcmd__install"
                ;;
            innernet__subcmd__help,list-associations)
                cmd="innernet__subcmd__help__subcmd__list__subcmd__associations"
                ;;
            innernet__subcmd__help,list-cidrs)
                cmd="innernet__subcmd__help__subcmd__list__subcmd__cidrs"
                ;;
            innernet__subcmd__help,override-endpoint)
                cmd="innernet__subcmd__help__subcmd__override__subcmd__endpoint"
                ;;
            innernet__subcmd__help,override-peer-endpoint)
                cmd="innernet__subcmd__help__subcmd__override__subcmd__peer__subcmd__endpoint"
                ;;
            innernet__subcmd__help,rename-cidr)
                cmd="innernet__subcmd__help__subcmd__rename__subcmd__cidr"
                ;;
            innernet__subcmd__help,rename-peer)
                cmd="innernet__subcmd__help__subcmd__rename__subcmd__peer"
                ;;
            innernet__subcmd__help,set-listen-port)
                cmd="innernet__subcmd__help__subcmd__set__subcmd__listen__subcmd__port"
                ;;
            innernet__subcmd__help,show)
                cmd="innernet__subcmd__help__subcmd__show"
                ;;
            innernet__subcmd__help,uninstall)
                cmd="innernet__subcmd__help__subcmd__uninstall"
                ;;
            innernet__subcmd__help,up)
                cmd="innernet__subcmd__help__subcmd__up"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        innernet)
            opts="-v -c -d -h -V --verbose --config-dir --data-dir --no-routing --backend --mtu --help --version install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer delete-peer forget-peer add-association delete-association list-associations set-listen-port override-endpoint override-peer-endpoint completions help"
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
        innernet__subcmd__add__subcmd__association)
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
        innernet__subcmd__add__subcmd__cidr)
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
        innernet__subcmd__add__subcmd__peer)
            opts="-h --name --ip --auto-ip --cidr --admin --yes --save-config --invite-expires --help"
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
        innernet__subcmd__completions)
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
        innernet__subcmd__delete__subcmd__association)
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
        innernet__subcmd__delete__subcmd__cidr)
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
        innernet__subcmd__delete__subcmd__peer)
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
        innernet__subcmd__disable__subcmd__peer)
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
        innernet__subcmd__down)
            opts="-h --help"
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
        innernet__subcmd__enable__subcmd__peer)
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
        innernet__subcmd__fetch)
            opts="-h --hosts-path --no-write-hosts --host-suffix --no-nat-traversal --exclude-nat-candidates --no-nat-candidates --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --hosts-path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-suffix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --exclude-nat-candidates)
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
        innernet__subcmd__forget__subcmd__peer)
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
        innernet__subcmd__help)
            opts="install show up fetch uninstall down add-peer rename-peer add-cidr rename-cidr delete-cidr list-cidrs disable-peer enable-peer delete-peer forget-peer add-association delete-association list-associations set-listen-port override-endpoint override-peer-endpoint completions help"
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
        innernet__subcmd__help__subcmd__add__subcmd__association)
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
        innernet__subcmd__help__subcmd__add__subcmd__cidr)
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
        innernet__subcmd__help__subcmd__add__subcmd__peer)
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
        innernet__subcmd__help__subcmd__completions)
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
        innernet__subcmd__help__subcmd__delete__subcmd__association)
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
        innernet__subcmd__help__subcmd__delete__subcmd__cidr)
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
        innernet__subcmd__help__subcmd__delete__subcmd__peer)
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
        innernet__subcmd__help__subcmd__disable__subcmd__peer)
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
        innernet__subcmd__help__subcmd__down)
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
        innernet__subcmd__help__subcmd__enable__subcmd__peer)
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
        innernet__subcmd__help__subcmd__fetch)
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
        innernet__subcmd__help__subcmd__forget__subcmd__peer)
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
        innernet__subcmd__help__subcmd__help)
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
        innernet__subcmd__help__subcmd__install)
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
        innernet__subcmd__help__subcmd__list__subcmd__associations)
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
        innernet__subcmd__help__subcmd__list__subcmd__cidrs)
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
        innernet__subcmd__help__subcmd__override__subcmd__endpoint)
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
        innernet__subcmd__help__subcmd__override__subcmd__peer__subcmd__endpoint)
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
        innernet__subcmd__help__subcmd__rename__subcmd__cidr)
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
        innernet__subcmd__help__subcmd__rename__subcmd__peer)
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
        innernet__subcmd__help__subcmd__set__subcmd__listen__subcmd__port)
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
        innernet__subcmd__help__subcmd__show)
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
        innernet__subcmd__help__subcmd__uninstall)
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
        innernet__subcmd__help__subcmd__up)
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
        innernet__subcmd__install)
            opts="-d -h --listen-port --hosts-path --no-write-hosts --host-suffix --name --default-name --delete-invite --no-nat-traversal --exclude-nat-candidates --no-nat-candidates --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --listen-port)
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
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --exclude-nat-candidates)
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
        innernet__subcmd__list__subcmd__associations)
            opts="-h --help"
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
        innernet__subcmd__list__subcmd__cidrs)
            opts="-t -h --tree --help"
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
        innernet__subcmd__override__subcmd__endpoint)
            opts="-e -u -h --endpoint --unset --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -e)
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
        innernet__subcmd__override__subcmd__peer__subcmd__endpoint)
            opts="-e -u -h --name --endpoint --unset --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -e)
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
        innernet__subcmd__rename__subcmd__cidr)
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
        innernet__subcmd__rename__subcmd__peer)
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
        innernet__subcmd__set__subcmd__listen__subcmd__port)
            opts="-l -u -h --listen-port --unset --yes --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --listen-port)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -l)
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
        innernet__subcmd__show)
            opts="-s -t -h --short --tree --help"
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
        innernet__subcmd__uninstall)
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
        innernet__subcmd__up)
            opts="-d -h --daemon --interval --hosts-path --no-write-hosts --host-suffix --no-nat-traversal --exclude-nat-candidates --no-nat-candidates --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --interval)
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
                --exclude-nat-candidates)
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
    complete -F _innernet -o nosort -o bashdefault -o default innernet
else
    complete -F _innernet -o bashdefault -o default innernet
fi
