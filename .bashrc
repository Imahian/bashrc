export PS1='\[\033[01;32m\]\u\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
export TERM=xterm

# alias
alias dir='dir --color=auto'
alias vdir='vdir --color=auto'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias ll='lsd -la --color=auto'
alias l='lsd -l --color=auto'
alias lll='lsd -lRFa --color=auto 2>/dev/null'
alias cat='batcat'
alias HTB='sudo /opt/htbExplorer/htbExplorer'
alias matrix='cmatrix -Boar -u 10'
alias acuario='/home/imahian/.acuario/acuario'
alias ..='cd ..'
alias ...='cd ../..'
alias act='source ~/.bashrc'
alias hrc='sudo cp -r /home/imahian/.bashrc /root/.bashrc'
alias update='sudo apt update'
alias upgrade='sudo apt install'
alias install='sudo apt install'
alias remove='sudo apt remove && sudo apt purge'
alias myip='curl -s ifconfig.me && echo'
alias untar='tar -zxvf'
alias software='uname -a && lsb_release -a && cat /etc/os-release'
alias hardware='sudo sh -c "lshw -short && dmicode -t memory && lspci -nnk && lsusb && lsblk"'
alias wireshark='sudo wireshark -stylesheet ~/.dark.css'
alias VPN='sudo openvpn /home/imahian/HTB/ImAhian.ovpn'
alias exploit='/opt/exploitdb/searchsploit'
alias onservices='sudo systemctl list-units --type=service --state=running'
alias android='/opt/genymobile/genymotion/genymotion'
alias rm='sudo rm -rf'
alias offservices='sudo systemctl list-units --type=service --state=inactive'
alias allservices='sudo service --status-all'
alias discord='/opt/Discord/Discord'
alias crackmapexec='cd /opt/CrackMapExec && poetry run crackmapexec'


#Extract Ports
function extractPorts(){
    ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
    ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
    echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
    echo -e "\t[*] IP Address: $ip_address"  >> extractPorts.tmp
    echo -e "\t[*] Open ports: $ports\n"  >> extractPorts.tmp
    echo $ports | tr -d '\n' | xclip -sel clip
    echo -e "[*] Ports copied to clipboard\n"  >> extractPorts.tmp
    cat extractPorts.tmp; rm extractPorts.tmp
}

function mkt() {
    mkdir nmap exploits content
}

# Función para monitorear procesos
function procmon {
  # Variables de colores
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  NC='\033[0m' # Sin color

  # Obtener la lista de todos los procesos en ejecución
  old_process="$(sudo ps -eo pid,command)"

  # Imprimir encabezado de la tabla
  printf "%-8s %-20s %-40s %-20s\n" "PID" "Proceso" "Archivo" "Servicio"

  while true; do
    sleep 1

    # Obtener la lista de procesos en ejecución
    new_process="$(sudo ps -eo pid,command)"

    # Obtener la diferencia entre los procesos antiguos y nuevos
    diff_output="$(diff <(echo "$old_process") <(echo "$new_process") | grep '[\>\<]' | grep -vE "command|procmon|kworker")"

    # Recorrer las líneas de la salida diferencial
    while IFS= read -r line; do
      symbol="$(echo "$line" | awk '{print $1}')"
      pid="$(echo "$line" | awk '{print $2}')"
      process_name="$(echo "$line" | awk '{$1=""; print $0}')"

      # Obtener el archivo ejecutable asociado al proceso
      if [ -e "/proc/$pid/exe" ]; then
        executable="$(sudo readlink -f "/proc/$pid/exe")"
        permissions="$(ls -l "$executable" | awk '{print $1}')"
      else
        executable="N/A"
        permissions="N/A"
      fi

      # Obtener el servicio asociado al proceso
      if [ -n "$executable" ]; then
        service="$(sudo systemctl --quiet is-active "$(basename "$executable")" && echo "Active")"
      else
        service=""
      fi

      # Imprimir la información en la tabla con colores
      if [ "$symbol" == ">" ]; then
        printf "%-8s ${GREEN}%-20s${NC} %-40s %-20s\n" "$pid" "$process_name" "$executable" "$service"
      elif [ "$symbol" == "<" ]; then
        printf "%-8s ${RED}%-20s${NC} %-40s %-20s\n" "$pid" "$process_name" "$executable" "$service"
      fi

    done <<< "$diff_output"

    # Actualizar la lista de procesos antiguos
    old_process="$new_process"
  done
}


function ip_scan() {
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  CYAN='\033[0;36m'
  NC='\033[0m' # No Color

  local subnet="192.168.1"

  echo -e "${RED}IP Address:${NC}"
  for ip in {1..255}; do
    local target_ip="$subnet.$ip"
    if ping -c 1 -w 1 "$target_ip" > /dev/null; then
      echo -e "  ${YELLOW}$target_ip${NC}"

      local os=$(sudo nmap -O "$target_ip" | grep "Running" | awk '{print $2}')
      if [[ -n $os ]]; then
        echo -e "    ${GREEN}OS Type:${NC} $os"
      fi

      local mac=$(sudo nmap -sn "$target_ip" | awk '/MAC Address:/{print $3}')
      if [[ -n $mac ]]; then
        echo -e "    ${GREEN}MAC Address:${NC} $mac"
      fi

      local company=$(sudo grep -i "^${mac:0:8}" /usr/share/nmap/nmap-mac-prefixes | awk -F '\t' '{print $2}')
      if [[ -n $company ]]; then
        echo -e "    ${GREEN}Company:${NC} $company"
      fi

      local hostname=$(sudo nmap -sL "$target_ip" | awk '/hostname/{print substr($0,index($0,$2))}')
      if [[ -n $hostname ]]; then
        echo -e "    ${GREEN}Hostname:${NC} $hostname"
      fi

      local open_ports=$(sudo nmap -sT -p- "$target_ip" | grep "open" | awk -F '/' '{print $1}' | xargs | sed 's/ /,/g')
      if [[ -n $open_ports ]]; then
        echo -e "    ${GREEN}Open Ports:${NC} $open_ports"
      fi

      echo ""
    fi
  done
}



check_os() {
    if [ "$#" -ne 1 ]; then
        echo -e "\n\e[31m[!] Uso: check_os <direccion-ip>\e[0m\n"
        return 1
    fi

    get_ttl() {
        out=$(ping -c 1 "$1" | awk '/ttl=/ {print $6}')
        ttl_value=$(echo "$out" | sed -n 's/ttl=\([0-9]\+\)/\1/p')
        echo "$ttl_value"
    }

    get_os() {
        ttl=$1

        if (( ttl >= 0 && ttl <= 64 )); then
            echo -e "\e[32mLinux\e[0m"
        elif (( ttl >= 65 && ttl <= 128 )); then
            echo -e "\e[34mWindows\e[0m"
        else
            echo -e "\e[33mNot Found\e[0m"
        fi
    }

    ip_address="$1"
    ttl=$(get_ttl "$ip_address")
    os_name=$(get_os "$ttl")
    echo -e "\e[32m$ip_address\e[0m (ttl -> \e[37m$ttl\e[0m): $os_name"
}


function tun0() {
    local vpn_ip=$(ip addr show dev tun0 2>/dev/null | awk '/inet / {print $2}')

    if [ -n "$vpn_ip" ]; then
        echo -e "\e[1;35mtun0 IP\e[0m: \e[1;31m$vpn_ip\e[0m"
    else
        echo -e "\e[31mNo VPN connection detected.\e[0m"
    fi
}
