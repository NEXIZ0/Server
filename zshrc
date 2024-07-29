


dnsrepo () {
    if [ -p /dev/stdin ]; then
        while IFS= read -r domain; do
            curl -s "https://dnsrepo.noc.org/?search=$domain" | grep -oP 'href="\K[^"]*' | awk -F'=' '{print $2}' | sed 's/\.$//g' | grep -Ei "($domain)$" | sort -u
        done
    else
        curl -s "https://dnsrepo.noc.org/?search=$1" | grep -oP 'href="\K[^"]*' | awk -F'=' '{print $2}' | sed 's/\.$//g' | grep -Ei "($1)$" | sort -u
    fi
}

#----------------------------------------------------------------------
kaeferjaeger() {
    if [ -p /dev/stdin ]; then
        while IFS= read -r domain; do
            for provider in amazon digitalocean google microsoft oracle; do
                curl -s "http://kaeferjaeger.gay/sni-ip-ranges/${provider}/ipv4_merged_sni.txt" |
                grep -oP "(?<=\[).*(?=\])" |
                tr ' ' '\n' |
                grep -F ".$domain" |
                sed 's/^\*\.//g' |
                grep -vF "*" |
                sort -u |
                anew "$domain".kaeferjaeger
            done
        done
    else
        for provider in amazon digitalocean google microsoft oracle; do
            curl -s "http://kaeferjaeger.gay/sni-ip-ranges/${provider}/ipv4_merged_sni.txt" |
            grep -oP "(?<=\[).*(?=\])" |
            tr ' ' '\n' |
            grep -F ".$1" |
            sed 's/^\*\.//g' |
            grep -vF "*" |
            sort -u |
            anew "$1".kaeferjaeger
        done
    fi
}


#---------------------------------------------------
refparam () {
	fallparams -u "$1" -c
	x8 -w parameters.txt -u "$1" -m 25 -X GET POST
	rm parameters.txt
	echo "#--------------------------------------------------"
	x8 -w /nexiz/Word-Listx/xss/full-parameters-xss.txt -u "$1" -m 40 -X GET POST
}


#--------------------------------------------------
sourcegraph () {
    # Check if input is from a pipe
    if [ -p /dev/stdin ]; then
        while IFS= read -r domain; do
            curl -s "https://sourcegraph.com/search/stream?q=$domain%20&v=V3&t=keyword&sm=0&display=1500&cm=t&max-line-len=5120" -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" | \
            grep -oE '\*?\b[a-z0-9]+([-\.][a-z0-9]+)*\.[a-z]{2,}\b' | \
            egrep -v "\.js|php|jpg|html|css|java|json|txt|swift|png|webp|svg" | \
            sort -u | \
            grep -Ei "$domain"
        done
    else
        curl -s "https://sourcegraph.com/search/stream?q=$1%20&v=V3&t=keyword&sm=0&display=1500&cm=t&max-line-len=5120" -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" | \
        grep -oE '\*?\b[a-z0-9]+([-\.][a-z0-9]+)*\.[a-z]{2,}\b' | \
        egrep -v "\.js|php|jpg|html|css|java|json|txt|swift|png|webp|svg" | \
        sort -u | \
        grep -Ei "$1"
    fi
}


#-----------------------------------------------------
clean_up (){
	find . -maxdepth 1 -type f | while read -r d; do cat "$d" | sed 's/\*//g; s/^\.//' > "${d}." && rm "$d"; done
	find . -maxdepth 1 -type f | while read -r file; do mv "$file" "$(echo "$file" | sed -E 's/\.$//; s/(.*)[[:space:]]+[^[:space:]]+(\.[^.]+)?$/\1\2/')"; done
	find . -maxdepth 1 -type f | while read d; do cat $d | sort -u > ${d}. && rm $d ; done
	find . -maxdepth 1 -type f | while read -r file; do mv "$file" "$(echo "$file" | sed -E 's/\.$//; s/(.*)[[:space:]]+[^[:space:]]+(\.[^.]+)?$/\1\2/')"; done
}

#----------------------------------------------------
#chaos-API-key
export PDCP_API_KEY=c090edee-2106-4f13-8653-8b5a0e9a573a
#-----------------------------------------------------

export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:/root/go/bin

#-----------------------------------------------------
crtsh_organ () {
    input=""
    while read line
    do
        curl -s "https://crt.sh/?O=$line%20Inc.&output=json" | jq -r ".[].common_name" | tr A-Z a-z | unfurl format %r.%t | sort -u
    done < "${1:-/dev/stdin}"
}



#-----------------------------------------------------
get_ip_prefix () {
    input=""
    while read line
    do
        curl -s https://api.bgpview.io/ip/$line | jq -r ".data.prefixes[0].prefix"
    done < "${1:-/dev/stdin}"
}

#-----------------------------------------------------
get_asn_details_ip () {
    input=""
    while read line
    do
        curl -s https://api.bgpview.io/asn/$line/prefixes | jq -r '.data.ipv4_prefixes[] | .prefix' | sort -u
    done < "${1:-/dev/stdin}"
}

#-----------------------------------------------------
get_ptr () {
    input=""
    while read line
    do
        ptr_record=$(curl -s https://api.bgpview.io/ip/$line | jq -r ".data.ptr_record")
        if [ "$ptr_record" != "null" ]; then
            echo "$ptr_record"
        fi
    done < "${1:-/dev/stdin}"
}

#-----------------------------------------------------
get_asn_details () {
    input=""
    while read line
    do
        curl -s https://api.bgpview.io/asn/$line | jq -r ".data | {asn: .asn, name: .name, des: .description_short, des_full: .description_full, email: .email_contacts, web: .website, abuse_contacts: .abuse_contacts}"
    done < "${1:-/dev/stdin}"
}
#-----------------------------------------------------

get_asn () {
    input=""
    while read line
    do
        curl -s https://api.bgpview.io/ip/$line | jq -r ".data.prefixes[] | {asn: .asn.asn, name: .asn.name}"
    done < "${1:-/dev/stdin}"
}

#-----------------------------------------------------
get_ip_asn () {
    input=""
    while read line
    do
        curl -s https://api.bgpview.io/ip/$line | jq -r ".data.prefixes[].asn.asn" | sort -u
    done < "${1:-/dev/stdin}"
}

#-----------------------------------------------------

httpx_full_silent () {
  if [ -z "$1" ]; then
    while IFS= read -r line; do
      echo "$line" | httpx -silent -follow-host-redirects -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" -H "Referer: https://$line" -threads 1
    done
  else
    echo "$1" | httpx -silent -follow-host-redirects -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firfox/108.0" -H "Referer: https://$1" -threads 1
  fi
}

#-----------------------------------------------------
httpx_full () {
  if [ -z "$1" ]; then
    while IFS= read -r line; do
      echo "$line" | httpx -silent -location -follow-host-redirects -title -status-code -cdn -tech-detect -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" -H "Referer: https://$line" -threads 1
    done
  else
    echo "$1" | httpx -silent -location -follow-host-redirects -title -status-code -cdn -tech-detect -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firfox/108.0" -H "Referer: https://$1" -threads 1
  fi
}
#-----------------------------------------------
get_certificate_nuclei () {
        input=""
        while read line
        do
                input="$input$line\n"
        done < "${1:-/dev/stdin}"
        echo $input | nuclei -t ~/ssl.yaml -silent -j | jq -r '.["extracted-results"][]'
}
#----------------------------------------------
get_certificate () {
        echo | openssl s_client -showcerts -servername $1 -connect $1:443 2> /dev/null | openssl x509 -inform pem -noout -text
}
#----------------------------------------------
nice_recollapse() {
    if [ -z "$1" ]; then
        echo "Usage: nice_recollapse <url>"
        return 1
    fi

    # Assign the first argument to user_url
    user_url="$1"

    # Run the recollapse commands and print success messages
    recollapse -p 1,2,4 -r 0x00,0x2F "$user_url" > "nice_recollapse.txt" && echo "generated 1"
    recollapse -p 1,2,4 -r 0x3A,0x40 "$user_url" >> "nice_recollapse.txt" && echo "generated 2"
    recollapse -p 1,2,4 -r 0x5C,0x60 "$user_url" >> "nice_recollapse.txt" && echo "generated 3"
    recollapse -p 1,2,4 -r 0x7B,0x7F "$user_url" >> "nice_recollapse.txt" && echo "generated 4"
}


#------------------------------------------------

wlist_maker () {
    seq 1 100 > list.tmp
    echo $1 >> list.tmp
    seq 101 300 >> list.tmp
    echo $1 >> list.tmp
    seq 301 600 >> list.tmp
}

#-----------------------------------------------

nice_katana () {
    while read line
    do
        host=$(echo $line | unfurl format %d)
        echo "$line" | katana -js-crawl -jsluice -known-files all -automatic-form-fill -silent -crawl-scope $host -extension-filter json,js,fnt,ogg,css,jpg,jpe,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,ml,ip | tee ${host}.katana
    done < "${1:-/dev/stdin}"
}

#-------------------------------------------------------

param_maker () {
    filename="$1"
    value="$2"
    counter=0
    query_string="?"
    while IFS= read -r keyword
    do
        if [ -n "$keyword" ]
        then
            counter=$((counter+1))
            query_string="${query_string}${keyword}=${value}${counter}&"
        fi
        if [ $counter -eq 25 ]
        then
            echo "${query_string%?}"
            query_string="?"
            counter=0
        fi
    done < "$filename"
    if [ $counter -gt 0 ]
    then
        echo "${quer_string%?}"
    fi
}

#-------------------------------------------------------
setopt autocd              # change directory just by typing its name
#setopt correct            # auto correct mistakes
setopt interactivecomments # allow comments in interactive mode
setopt magicequalsubst     # enable filename expansion for arguments of the form ‘anything=expression’
setopt nonomatch           # hide error message if there is no match for the pattern
setopt notify              # report the status of background jobs immediately
setopt numericglobsort     # sort filenames numerically when it makes sense
setopt promptsubst         # enable command substitution in prompt

WORDCHARS=${WORDCHARS//\/} # Don't consider certain characters part of the word

# hide EOL sign ('%')
PROMPT_EOL_MARK=""

# configure key keybindings
bindkey -e                                        # emacs key bindings
bindkey ' ' magic-space                           # do history expansion on space
bindkey '^U' backward-kill-line                   # ctrl + U
bindkey '^[[3;5~' kill-word                       # ctrl + Supr
bindkey '^[[3~' delete-char                       # delete
bindkey '^[[1;5C' forward-word                    # ctrl + ->
bindkey '^[[1;5D' backward-word                   # ctrl + <-
bindkey '^[[5~' beginning-of-buffer-or-history    # page up
bindkey '^[[6~' end-of-buffer-or-history          # page down
bindkey '^[[H' beginning-of-line                  # home
bindkey '^[[F' end-of-line                        # end
bindkey '^[[Z' undo                               # shift + tab undo last action

# enable completion features
autoload -Uz compinit
compinit -d ~/.cache/zcompdump
zstyle ':completion:*:*:*:*:*' menu select
zstyle ':completion:*' auto-description 'specify: %d'
zstyle ':completion:*' completer _expand _complete
zstyle ':completion:*' format 'Completing %d'
zstyle ':completion:*' group-name ''
zstyle ':completion:*' list-colors ''
zstyle ':completion:*' list-prompt %SAt %p: Hit TAB for more, or the character to insert%s
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
zstyle ':completion:*' rehash true
zstyle ':completion:*' select-prompt %SScrolling active: current selection at %p%s
zstyle ':completion:*' use-compctl false
zstyle ':completion:*' verbose true
zstyle ':completion:*:kill:*' command 'ps -u $USER -o pid,%cpu,tty,cputime,cmd'

# History configurations
HISTFILE=~/.zsh_history
HISTSIZE=1000
SAVEHIST=2000
setopt hist_expire_dups_first # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt hist_ignore_dups       # ignore duplicated commands history list
setopt hist_ignore_space      # ignore commands that start with space
setopt hist_verify            # show command with history expansion to user before running it
#setopt share_history         # share command history data
alias nice_passive="/sec/root/Desktop/tools/nice_passive/nice_passive.py"

# force zsh to show the complete history
alias history="history 0"

# configure `time` format
TIMEFMT=$'\nreal\t%E\nuser\t%U\nsys\t%S\ncpu\t%P'

# make less more friendly for non-text input files, see lesspipe(1)
#[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        # We have color support; assume it's compliant with Ecma-48
        # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
        # a case would tend to support setf rather than setaf.)
        color_prompt=yes
    else
        color_prompt=
    fi
fi

configure_prompt() {
    prompt_symbol=㉿
    # Skull emoji for root terminal
    [ "$EUID" -eq 0 ] && prompt_symbol=💀
    case "$PROMPT_ALTERNATIVE" in
        twoline)
            PROMPT=$'%F{%(#.blue.green)}┌──${debian_chroot:+($debian_chroot)─}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))─}(%B%F{%(#.red.blue)}%n'$prompt_symbol$'%m%b%F{%(#.blue.green)})-[%B%F{reset}%(6~.%-1~/…/%4~.%5~)%b%F{%(#.blue.green)}]\n%{%G└%}%{%G─%}%B%(#.%F{red}#.%F{blue}$)%b%F{reset} '
            # Right-side prompt with exit codes and background processes
            #RPROMPT=$'%(?.. %? %F{red}%B⨯%b%F{reset})%(1j. %j %F{yellow}%B⚙%b%F{reset}.)'
            ;;
        oneline)
            PROMPT=$'${debian_chroot:+($debian_chroot)}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))}%B%F{%(#.red.blue)}%n@%m%b%F{reset}:%B%F{%(#.blue.green)}%~%b%F{reset}%(#.#.$) '
            RPROMPT=
            ;;
        backtrack)
            PROMPT=$'${debian_chroot:+($debian_chroot)}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))}%B%F{red}%n@%m%b%F{reset}:%B%F{blue}%~%b%F{reset}%(#.#.$) '
            RPROMPT=
            ;;
    esac
    unset prompt_symbol
}

# The following block is surrounded by two delimiters.
# These delimiters must not be modified. Thanks.
# START KALI CONFIG VARIABLES
PROMPT_ALTERNATIVE=twoline
NEWLINE_BEFORE_PROMPT=yes
# STOP KALI CONFIG VARIABLES

if [ "$color_prompt" = yes ]; then
    # override default virtualenv indicator in prompt
    VIRTUAL_ENV_DISABLE_PROMPT=1

    configure_prompt

    # enable syntax-highlighting
    if [ -f /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]; then
        . /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
        ZSH_HIGHLIGHT_HIGHLIGHTERS=(main brackets pattern)
        ZSH_HIGHLIGHT_STYLES[default]=none
        ZSH_HIGHLIGHT_STYLES[unknown-token]=underline
        ZSH_HIGHLIGHT_STYLES[reserved-word]=fg=cyan,bold
        ZSH_HIGHLIGHT_STYLES[suffix-alias]=fg=green,underline
        ZSH_HIGHLIGHT_STYLES[global-alias]=fg=green,bold
        ZSH_HIGHLIGHT_STYLES[precommand]=fg=green,underline
        ZSH_HIGHLIGHT_STYLES[commandseparator]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[autodirectory]=fg=green,underline
        ZSH_HIGHLIGHT_STYLES[path]=bold
        ZSH_HIGHLIGHT_STYLES[path_pathseparator]=
        ZSH_HIGHLIGHT_STYLES[path_prefix_pathseparator]=
        ZSH_HIGHLIGHT_STYLES[globbing]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[history-expansion]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[command-substitution]=none
        ZSH_HIGHLIGHT_STYLES[command-substitution-delimiter]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[process-substitution]=none
        ZSH_HIGHLIGHT_STYLES[process-substitution-delimiter]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[single-hyphen-option]=fg=green
        ZSH_HIGHLIGHT_STYLES[double-hyphen-option]=fg=green
        ZSH_HIGHLIGHT_STYLES[back-quoted-argument]=none
        ZSH_HIGHLIGHT_STYLES[back-quoted-argument-delimiter]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[single-quoted-argument]=fg=yellow
        ZSH_HIGHLIGHT_STYLES[double-quoted-argument]=fg=yellow
        ZSH_HIGHLIGHT_STYLES[dollar-quoted-argument]=fg=yellow
        ZSH_HIGHLIGHT_STYLES[rc-quote]=fg=magenta
        ZSH_HIGHLIGHT_STYLES[dollar-double-quoted-argument]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[back-double-quoted-argument]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[back-dollar-quoted-argument]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[assign]=none
        ZSH_HIGHLIGHT_STYLES[redirection]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[comment]=fg=black,bold
        ZSH_HIGHLIGHT_STYLES[named-fd]=none
        ZSH_HIGHLIGHT_STYLES[numeric-fd]=none
        ZSH_HIGHLIGHT_STYLES[arg0]=fg=cyan
        ZSH_HIGHLIGHT_STYLES[bracket-error]=fg=red,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-1]=fg=blue,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-2]=fg=green,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-3]=fg=magenta,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-4]=fg=yellow,bold
        ZSH_HIGHLIGHT_STYLES[bracket-level-5]=fg=cyan,bold
        ZSH_HIGHLIGHT_STYLES[cursor-matchingbracket]=standout
    fi
else
    PROMPT='${debian_chroot:+($debian_chroot)}%n@%m:%~%(#.#.$) '
fi
unset color_prompt force_color_prompt

toggle_oneline_prompt(){
    if [ "$PROMPT_ALTERNATIVE" = oneline ]; then
        PROMPT_ALTERNATIVE=twoline
    else
        PROMPT_ALTERNATIVE=oneline
    fi
    configure_prompt
    zle reset-prompt
}
zle -N toggle_oneline_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*|Eterm|aterm|kterm|gnome*|alacritty)
    TERM_TITLE=$'\e]0;${debian_chroot:+($debian_chroot)}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))}%n@%m: %~\a'
    ;;
*)
    ;;
esac

precmd() {
    # Print the previously configured title
    print -Pnr -- "$TERM_TITLE"

    # Print a new line before the prompt, but only if it is not the first line
    if [ "$NEWLINE_BEFORE_PROMPT" = yes ]; then
        if [ -z "$_NEW_LINE_BEFORE_PROMPT" ]; then
            _NEW_LINE_BEFORE_PROMPT=1
        else
            print ""
        fi
    fi
}

# enable color support of ls, less and man, and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    export LS_COLORS="$LS_COLORS:ow=30;44:" # fix ls color for folders with 777 permissions

    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
    alias diff='diff --color=auto'
    alias ip='ip --color=auto'

    export LESS_TERMCAP_mb=$'\E[1;31m'     # begin blink
    export LESS_TERMCAP_md=$'\E[1;36m'     # begin bold
    export LESS_TERMCAP_me=$'\E[0m'        # reset bold/blink
    export LESS_TERMCAP_so=$'\E[01;33m'    # begin reverse video
    export LESS_TERMCAP_se=$'\E[0m'        # reset reverse video
    export LESS_TERMCAP_us=$'\E[1;32m'     # begin underline
    export LESS_TERMCAP_ue=$'\E[0m'        # reset underline

    # Take advantage of $LS_COLORS for completion as well
    zstyle ':completion:*' list-colors "${(s.:.)LS_COLORS}"
    zstyle ':completion:*:*:kill:*:processes' list-colors '=(#b) #([0-9]#)*=0=01;31'
fi

# some more ls aliases
alias ll='ls -l'
alias la='ls -A'
alias l='ls -CF'

# enable auto-suggestions based on the history
if [ -f /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh ]; then
    . /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
    # change suggestion color
    ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=#999'
fi

# enable command-not-found if installed
if [ -f /etc/zsh_command_not_found ]; then
    . /etc/zsh_command_not_found
fi
[[ -e /etc/shellrc ]] && source /etc/shellrc


#---------------------------------------------------------------------
dns_brute_full () {
        echo "[!] cleaning..."
        rm -f "$1.wordlist $1.dns_gen"
	echo "[!] making static world list..."
	curl -s https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt -o best-dns-wordlist.txt && curl -s https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt -o 2m-subdomains.txt && crunch 1 4 abcdefghijklmnopqrstuvwxyz1234567890 > 4-word.txt && cat best-dns-wordlist.txt 4-word.txt 2m-subdomains.txt | tr '[:upper:]' '[:lower:]' | sort -u > static-dns-brute.worldlist.txt && rm 2m-subdomains.txt 4-word.txt best-dns-wordlist.txt
	awk -v domain="$1" '{print $0"."domain}' "static-dns-brute.worldlist.txt" >> "$1.wordlist"
	rm static-dns-brute.worldlist.txt
	echo "[!] Start shuffledns static brute-force..."
	shuffledns -mode resolve -t 100 -silent -list $1.wordlist -d $1 -r ~/.resolver -m $(which massdns) | tee $1.dns_brute 2>&1 > /dev/null
	echo "[+] finished shuffledns Static, total $(wc -l $1.dns_brute) resolved..."
	echo "[!] running subfinder..."
	subfinder -d $1 -all -silent | dnsx -t 20 -retry 3 -r ~/.resolver -silent | anew $1.dns_brute 2>&1 > /dev/null
	echo "[+] finished, total $(wc -l $1.dns_brute) resolved..."
	echo "[!] Make word list ( dnsjen + altdns )"
	curl -s https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -o altdns-words.txt && curl -s https://raw.githubusercontent.com/ProjectAnte/dnsgen/master/dnsgen/words.txt -o dnsgen-words.txt && cat altdns-words.txt dnsgen-words.txt | sort -u > words-merged.txt && echo "2020\n2021\n2022\n2023\n2024\n2025" >> words-merged.txt && rm altdns-words.txt dnsgen-words.txt
	echo "[!] running DNSGen..."
	cat $1.dns_brute | dnsgen -w words-merged.txt - | egrep -v "^\." | egrep -v ".*\.\..*" | egrep -v ".*\-\..*" | egrep -v "^\-" | sort -u > $1.dns_gen 2>&1 > /dev/null
	echo "[+] finished with $(wc -l $1.dns_gen) words..."
	echo "[!] shuffledns dynamic brute-force on dnsgen results..."
	shuffledns -mode resolve -t 100 -silent -list $1.dns_gen -d $1 -r ~/.resolver -m $(which massdns) | anew $1.dns_brute 2>&1 > /dev/null
	echo "[+] finished, total $(wc -l $1.dns_brute) resolved..."
	rm $1.dns_gen $1.wordlist words-merged.txt
}
#-------------------------------------------------------------------------------------
crtsh () {
    query=$(cat <<-END
        SELECT
            ci.NAME_VALUE
        FROM
            certificate_and_identities ci
        WHERE
            plainto_tsquery('certwatch', '$1') @@ identities(ci.CERTIFICATE)
END
)
    echo "$query" | psql -t -h crt.sh -p 5432 -U guest certwatch | sed 's/ //g' | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn,.idea,.tox} -E --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn,.idea,.tox} ".*.\.$1" | sed 's/*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u
}
#-------------------------------------------------------------------------------------
abuseipdb () {
    curl -s "https://www.abuseipdb.com/whois/$1" -H "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36" -b "abuseipdb_session=YOUR-SESSION" | grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn,.idea,.tox} --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn,.idea,.tox} -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed "s|$|.$1|"
}
#------------------------------------------------------------------------------------
