

#!/bin/bash

source /etc/bash_completion

#Alias
alias la='lsd -la --color=auto'
alias ll='lsd -l --color=auto'
alias l='lsd --color=auto'
alias ls='lsd -l --color=auto'
alias cat='batcat'
alias HTB='sudo /opt/htbExplorer/htbExplorer'


# User specific aliases and functions

# Colores para la terminal
export PS1='\[\033[01;32m\]\u\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
# Predicción de sintaxis
if [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi

# Agrega aquí tus propias funciones

# Función que maneja las diferentes tareas
function htb_task() {
    # Verificar que se hayan ingresado los parámetros
    if [ $# -lt 2 ]; then
        echo "Usage: htb_task [-d|-k|-r|-f] machine_name [flag]"
        return 1
    fi
    
    # Definir las credenciales de la API
    HTB_API_KEY='Cq00AywTIno5D4RBa3N3Y9xt040ZouCU913Hs1AKpUjjAUUO34atZOKTQq4W'
    HTB_API_SECRET='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiI1IiwianRpIjoiM2FiNWZjZjI3NWNjN2NkNWFmMzRiYmQ1NDUwYzcyZjc0MTA1OGFmNDgyMDhkMTFkNzE5MThjZWY2YTFlNTJiYzA5N2RjYjIzMDkwOTEwMjgiLCJpYXQiOjE2ODE1NDI3NDcuNjcxNDkzLCJuYmYiOjE2ODE1NDI3NDcuNjcxNDk0LCJleHAiOjE2ODY3MjY3NDcuNjY4MDczLCJzdWIiOiIxMDg4NDUxIiwic2NvcGVzIjpbIjJmYSJdfQ.oooCUdXqevhqVXTQTJFBcx2upJkyGtt_6CeGlRhoPdCJaR2edjLOvpvoPq3Mzi3hUuXdmhGf74ZIVR2P_QRgIujAoeNYDKRb3GGeO6FVpgUy5n5qwcQ0NIh4xqnc5WamkrfVsPBE_vtM2jhVOPgvUEY63NhW7iP0N_pjsYiQkQLPDgV7jDuDXw7qY05wAe7mJviGrONvcM6l5OdpQfkMj1UU5Z0-vKIVS6IacGkBLWlptjkwv24QeF2Qf8R50tgks7ScuZO2mmL_cTc-dMoURjv-MJqi4_6IWVkyQjyyMQ_aO5uvhYp-MS9jTelJRyH4G-h3dSLtXRH4EXfn6prcHJCGAeOBJPVX1qJybg3B-ucYiBOWvbmNkpYqAM5jXSJgFSobon3EPPUZ3UHqzduoqPBg4S1wjyqZ1PrhPBxRQqsLPlvfwlvwPNJ2n_dt_lNvbHmC1u0HaB-sZqwuybkjHdO4H2JGAGCXt9xe58djfhbIg9opDPPiF3Kn6YX-sZv4siW0lqijNRhGjszLI0sYLznQgiPK8ji9mD3UjcpBk0LQOvveoX6kTbl8Vrb5rttSr8hJ3iz1DCsWX6Ri8YtwMtv5hJJXObrc_K3uxt2V2IF7Chun1kC021J_hv8c6fe2Pw5geodwyKBvaxdXlqqW2V-0Ly41HiXMGqCfLXD8iAE'
    
    # Verificar si se está deployando una máquina
    if [ "$1" == "-d" ]; then
        htbapi machine deploy $2
        echo "Machine $2 deployed successfully"
    # Verificar si se está deteniendo una máquina
    elif [ "$1" == "-k" ]; then
        htbapi machine stop $2
        echo "Machine $2 stopped successfully"
    # Verificar si se está reiniciando una máquina
    elif [ "$1" == "-r" ]; then
        htbapi machine reset $2
        echo "Machine $2 reset successfully"
    # Verificar si se está actualizando la flag de una máquina
    elif [ "$1" == "-f" ]; then
        # Verificar que se haya ingresado la flag
        if [ -z "$3" ]; then
            echo "Please enter the flag"
            return 1
        fi
        htbapi machine update_flag $2 $3
        echo "Flag updated successfully for machine $2"
    # Si se ingresa un parámetro inválido
    else
        echo "Invalid parameter"
        return 1
    fi
}



# Función para mostrar la ruta completa con 'pwd' o solo el símbolo '$'
function show_pwd {
    if [ "$1" == "pwd" ]; then
        echo $(pwd)
    else
        echo "\$"
    fi
}

function hash_scan_network() {
    # Verificar si Hashcat y Hash-Identifier están instalados
    if ! command -v hashcat >/dev/null 2>&1 || ! command -v hash-identifier >/dev/null 2>&1; then
        echo "Hashcat and/or Hash-Identifier is not installed. Please install them and try again."
        return 1
    fi

    # Buscar dispositivos en la red
    echo "Scanning network for devices..."
    devices=$(nmap -sn 192.168.1.0/24 | grep "Nmap scan report for" | cut -d " " -f 5)

    # Si no se encontraron dispositivos, mostrar mensaje y salir
    if [[ -z "$devices" ]]; then
        echo "No devices were found on the network."
        return 1
    fi

    # Mostrar dispositivos encontrados y solicitar selección
    echo "The following devices were found on the network:"
    select device in $devices "Cancel"; do
        if [[ -n "$device" ]]; then
            break
        fi
    done

    # Si se selecciona "Cancel", salir
    if [[ "$device" == "Cancel" ]]; then
        echo "Operation canceled."
        return 1
    fi

    # Buscar hashes en los archivos de la carpeta actual para el dispositivo seleccionado
    echo "Searching for hashes in the current directory for $device..."
    hash_files=$(grep -r -l "^\([a-fA-F0-9]\{32\}\)\|\([a-fA-F0-9]\{40\}\)\|\([a-fA-F0-9]\{64\}\)\|\([a-fA-F0-9]\{96\}\)\|\([a-fA-F0-9]\{128\}\)$" ./* | cut -d: -f1 | sort -u)

    # Si no se encontraron hashes, mostrar mensaje y salir
    if [[ -z "$hash_files" ]]; then
        echo "No hashes were found in the current directory for $device."
        return 1
    fi

    # Mostrar hashes encontrados y solicitar selección
    echo "The following hashes were found in the current directory for $device:"
    select hash_file in $hash_files "Cancel"; do
        if [[ -n "$hash_file" ]]; then
            break
        fi
    done

    # Si se selecciona "Cancel", salir
    if [[ "$hash_file" == "Cancel" ]]; then
        echo "Operation canceled."
        return 1
    fi

    # Identificar el tipo de hash
    hash_type=$(hash-identifier "$hash_file" | grep "Possible Hashs" | cut -d ":" -f 2- | tr -d ' ')

    # Si no se pudo identificar el tipo de hash, mostrar mensaje y salir
    if [[ -z "$hash_type" ]]; then
        echo "Unable to identify the hash type."
        return 1
    fi

    # Ejecutar hashcat para buscar el hash
    echo "Running hashcat to find the hash..."
    hashcat -m "$hash_type" -a 0 "$hash_file" "$device".txt

    # Mostrar el resultado de hashcat
    echo "Hashcat result:"
    cat "$device".txt

    # Eliminar el archivo de salida de hashcat
    rm "$device".txt
}


function scan_and_decrypt() {
    sudo tshark -i wlx00e04c198b02 -T fields -e frame.protocols -e ip.src -e tcp.port -e tcp.dstport -e data |
    while read protocols ipaddr srcport dstport data; do
        # Check if the data is encrypted
        hash_type=$(echo "$data" | hashid | grep -oP "(?<=\[\+\]\s)[a-zA-Z0-9-]+(?=\s*\[)") 
        if [ -n "$hash_type" ]; then
            # Decrypt the data
            decrypted=$(echo "$data" | hashcat -m $(echo "$hash_type" | tr -d '-') -a 0 /path/to/dictionary.txt)
            # Print the decrypted data if it's printable
            if [[ "$decrypted" =~ ^[[:print:]]+$ ]]; then
                echo "| $protocols | $ipaddr | $dstport | $decrypted | $(echo "$data" | md5sum | cut -d ' ' -f 1) |"
            else
                echo "| $protocols | $ipaddr | $dstport | $data | $(echo "$data" | md5sum | cut -d ' ' -f 1) |"
            fi
        fi
    done
}


# Función para buscar hashes en tiempo real en la red
function look_hashes() {
    # Comenzamos la captura de paquetes en la red
    sudo tshark -i wlx00e04c198b02 -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e data -Y "tcp and data" |
    while read src_ip dst_ip src_port dst_port data; do
        # Buscamos hashes en la data del paquete
        hashes=$(echo "$data" | hashid | grep "Hashes")

        # Si hay hashes, los buscamos con hashcat
        if [[ $hashes != "" ]]; then
            # Imprimimos los detalles del paquete y los hashes encontrados
            echo "| $src_ip | $src_port | $dst_ip | $dst_port | $data |"
            echo "|------------|------------|------------|------------|----------------------|"
            echo "| Protocol   | IP Address | Port       | Hash       | Data decrypted      |"
            echo "|------------|------------|------------|------------|----------------------|"
            echo "$data" | hashid --quiet | grep "Hashes" | awk '{print $2}' | 
            while read hash_type; do
                hashcat -m "$hash_type" --show <<< "$data" | awk -v hash_type="$hash_type" -v src_ip="$src_ip" -v dst_ip="$dst_ip" -v src_port="$src_port" -v dst_port="$dst_port" '{printf("| %10s | %10s | %10s | %10s | %30s | %30s |\n", hash_type, src_ip, src_port, dst_port, $1, $2)}'
            done
            echo "|------------|------------|------------|------------|----------------------|"
            echo ""
        fi
    done
}

function decrypt_network_hashes() {
    # Busca todos los hashes en la red local
    for ip in $(sudo nmap -sT -p- 192.168.1.0/24 | grep "open" | awk -F '/' '{print $1}')
    do
        echo "Analizando la IP: $ip"
        # Verifica qué protocolo está usando la IP
        protocol=$(sudo tshark -n -i eth0 -f "host $ip" -Y "ssl or ssh" -T fields -e ssl.handshake.extensions_server_name)
        if [[ $protocol == "" ]]; then
            protocol=$(sudo tshark -n -i eth0 -f "host $ip" -Y "tcp" -T fields -e http.host 2>/dev/null | head -1)
            if [[ $protocol == "" ]]; then
                protocol=$(sudo tshark -n -i eth0 -f "host $ip" -Y "udp" -T fields -e dns.qry.name 2>/dev/null | head -1)
            fi
        fi
        # Si se encontró un protocolo, busca los hashes en todos los puertos de la IP
        if [[ $protocol != "" ]]; then
            echo "Protocolo detectado: $protocol"
            for port in $(sudo nmap -p- --min-rate=1000 -T4 $ip | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
            do
                sudo tshark -n -i eth0 -f "host $ip and port $port" -Y "ssl.handshake.certificate and tcp.payload" -T fields -e data |
                while read data; do
                    hash_type=$(echo $data | awk '{print $1}')
                    hash=$(echo $data | awk '{print $2}')
                    # Si se encuentra un hash, intenta desencriptarlo
                    if [[ $hash_type != "" && $hash != "" ]]; then
                        echo "Hash encontrado: $hash_type en el puerto $port"
                        decr=$(sudo hashcat --force --status --status-timer=30 -m $hash_type -a 0 $hash /usr/share/wordlists/rockyou.txt 2>/dev/null)
                        decr=$(echo $decr | awk -F ': ' '{print $3}')
                        if [[ $decr != "" ]]; then
                            echo "| $(printf '%-15s' "$hash_type") | $(printf '%-15s' "$ip") | $(printf '%-5s' "$port") | $(printf '%-20s' "$hash") | $(printf '%-20s' "$decr") |"
                        fi
                    fi
                done &
            done
        fi
    done
}

function search_exploit() {
    # Comprobar que se ha proporcionado un argumento de búsqueda
    if [ $# -eq 0 ]; then
        echo "Usage: search_exploit <search term>"
        return 1
    fi

    # Ejecutar searchsploit con el argumento de búsqueda
    sudo /usr/bin/exploitdb/searchsploit "$1"
}


function capturar_ssid {
  if [[ -z "$1" ]]; then
    echo "Uso: capturar_ssid <interfaz>"
    return 1
  fi

  echo "Iniciando detección de redes WiFi..."
  sudo airodump-ng "$1" --output-format csv -w dump --write-interval 2 > /dev/null &
  sleep 10
  sudo pkill airodump-ng
  echo "Redes encontradas:"
  awk -F "\"*,\"*" '/WPA/ {print $14 " [" $1 "]" }' dump-01.csv | sort -u
  rm dump-01.csv
}

function detectar_wifi() {
  echo "Iniciando airodump-ng..."
  echo "Presiona Ctrl+C para detener la detección."

  # Pedir al usuario que seleccione una interfaz
  interfaces=$(ifconfig | grep "^[a-zA-Z0-9]" | awk '{print $1}')
  echo "Por favor seleccione una interfaz Wi-Fi:"
  select interfaz in $interfaces; do
    if [[ -n $interfaz ]]; then
      break
    fi
  done

  # Pedir al usuario que especifique los filtros
  echo "Por favor especifique los filtros presione Enter si no desea agregar filtros:"
  read filtros

  # Ejecutar airodump-ng con los filtros especificados
  sudo airodump-ng $interfaz $filtros --output-format csv --write dump

  # Pedir al usuario que seleccione qué información quiere ver
  while true; do
    echo "¿Qué información quieres ver?"
    echo "1. Lista de redes detectadas"
    echo "2. Lista de clientes conectados a las redes"
    echo "3. Lista de clientes que han enviado tráfico"
    echo "4. Salir"
    read opcion

    # Mostrar la información seleccionada
    case $opcion in
      1)
        echo "Listado de redes detectadas:"
        awk -F "," '!x[$14]++ {print $14 "," $1 "," $4 "," $6 "," $7}' dump-01.csv | sort
        ;;
      2)
        echo "Listado de clientes conectados a las redes:"
        awk -F "," '!x[$1]++ {print $1 "," $4 "," $3 "," $6}' dump-01.csv | sort
        ;;
      3)
        echo "Listado de clientes que han enviado tráfico:"
        awk -F "," '!x[$1]++ {print $1 "," $4 "," $6}' dump-01.csv | sort
        ;;
      4)
        echo "Deteniendo airodump-ng..."
        sudo pkill airodump-ng
        rm dump-01.csv
        return
        ;;
      *)
        echo "Opción inválida."
        ;;
    esac
  done
}


function search_website() {
    echo "Ingrese la URL del sitio web que desea buscar:"
    read url

    echo "Ingrese la opción de búsqueda que desea realizar:"
    echo "1. Cookies"
    echo "2. API endpoints"
    echo "3. Imágenes"
    echo "4. URLs"
    echo "5. Escaneo de puertos Nmap"
    echo "6. Escaneo de vulnerabilidades OpenVAS"
    echo "7. Fuerza bruta de directorios Gobuster"
    echo "8. Fuerza bruta de parámetros Fuzz"
    read option

    case $option in
        1)
            echo "Buscando cookies en $url..."
            sudo curl -I -c - "$url" | grep "Set-Cookie"
            ;;
        2)
            echo "Buscando API endpoints en $url..."
            sudo curl "$url" | grep -oP "https?://?[\w/\-?=%.]+\.[\w/\-?=%.]+"
            ;;
        3)
            echo "Buscando imágenes en $url..."
            sudo curl "$url" | grep -oP '(?<=<img src=")[^"]*(?=")'
            ;;
        4)
            echo "Buscando URLs en $url..."
            sudo curl -s "$url" | grep -oP '(?<=href=")[^"]*(?=")' | sed "s|^/|$url/|"
            ;;
        5)
            echo "Ejecutando escaneo de puertos en $url..."
            sudo nmap -sS "$url" | grep -E "^[0-9]+\/tcp"
            ;;
        6)
            echo "Ejecutando escaneo de vulnerabilidades en $url..."
            sudo omp -u admin -w password -T 5 -c "$url"
            echo "Ejecución del escaneo finalizada."
            ;;
        7)
            echo "Ejecutando fuerza bruta de directorios en $url..."
            sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -u "$url" -x php,txt,html -o gobuster_result.txt
            cat gobuster_result.txt | grep -E 'Status: 200' | awk '{print $2}' | sort -u
            ;;
        8)
            echo "Ejecutando fuerza bruta de parámetros en $url..."
            sudo wfuzz -c -u "$url" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 | grep -v '404 Not Found' | grep -v '0 chars'
            ;;
        *)
            echo "Opción no válida."
            ;;
    esac
}


function capture_macs_traffic() {
    echo "Ingrese la duración de la captura en segundos:"
    read duration

    echo "Ingrese la dirección MAC que desea buscar:"
    read mac_address

    echo "Ingrese el tipo de protocolo que desea buscar (http, dns, ssl, ssh, ftp):"
    read protocol_type

    filter=""
    case "$protocol_type" in
        "http") filter="http.request or http.response";;
        "dns") filter="dns";;
        "ssl") filter="ssl";;
        "ssh") filter="ssh";;
        "ftp") filter="ftp";;
        *) echo "Protocolo no válido"; exit 1;;
    esac

    sudo tshark -i wlx00e04c198b02 -f "ether host $mac_address or ether multicast or ether broadcast" -T fields -e frame.time -e eth.src -e eth.dst -e ip.src -e ip > captured_traffic.txt
}



function graph_network() {
  echo "Generando el diagrama de la red..."
  sudo lsof -i -P -n | grep LISTEN > network.txt
  cat network.txt | awk '{ print $2 }' | uniq > network_pids.txt
  echo "digraph network {" > network.dot
  cat network_pids.txt | while read line; do
    name=`ps -p $line -o comm=`
    echo "\"$name\" [label=\"$name ($line)\"]" >> network.dot
    sudo lsof -a -p $line -i -P -n | awk '{ print "\""$1"\" -> \""$3"\" [label=\""$8" "$9" "$10"\"]" }' >> network.dot
  done
  echo "" >> network.dot
  dot -Tpng network.dot | feh -
  echo "Presiona Ctrl+C para salir"
  rm network.txt network_pids.txt network.dot
}



function system_integrity_check() {
    # Comprobar si se han modificado los archivos del sistema
    system_files=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -mtime -7)
    modified_files=""
    for file in $system_files; do
        file_hash=$(md5sum $file | awk '{print $1}')
        original_hash=$(grep $file /var/log/dpkg.log* | tail -1 | awk '{print $3}')
        if [ "$file_hash" != "$original_hash" ]; then
                    modified_files="$modified_files $file"
        fi
    done
    if [ -n "$modified_files" ]; then
        echo "Los siguientes archivos del sistema han sido modificados recientemente:"
        echo $modified_files
    else
        echo "No se han encontrado modificaciones recientes en los archivos del sistema."
    fi

    # Comprobar si hay puertos abiertos inesperados
    open_ports=$(netstat -an | grep LISTEN | awk '{print $4}' | grep -v 127.0.0.1 | awk -F':' '{print $2}' | sort -u)
    suspicious_ports=""
    for port in $open_ports; do
        if [ $port -lt 1024 ]; then
            suspicious_ports="$suspicious_ports $port"
        fi
    done
    if [ -n "$suspicious_ports" ]; then
        echo "Los siguientes puertos abiertos son sospechosos:"
        echo $suspicious_ports
    else
        echo "No se han encontrado puertos sospechosos abiertos."
    fi
}


function analyze_network() {
    while true; do
        echo "1. Mostrar tráfico de red TCP"
        echo "2. Mostrar tráfico de red UDP"
        echo "3. Escanear puertos de un host"
        echo "4. Descubrir hosts en una red local"
        echo "5. Escanear servicios y tecnologías en un host"
        echo "6. Salir"
        read -p "Ingrese la opción deseada: " option
        case $option in
            1)
                sudo tcpdump -i any -A -s 0 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0' 2>/dev/null | while read line; do
                    analyze_network_traffic "$line"
                done
                ;;
            2)
                sudo tcpdump -i any -A -s 0 'udp' 2>/dev/null | while read line; do
                    analyze_network_traffic "$line"
                done
                ;;
            3)
                read -p "Ingrese el host a escanear: " host
                sudo nmap -p- -T4 -v $host
                ;;
            4)
                read -p "Ingrese la red a escanear (formato CIDR, ej: 192.168.0.0/24): " network
                sudo nmap -sn $network
                ;;
            5)
                read -p "Ingrese el host a escanear: " host
                sudo nmap -sV --script=http-headers,ssl-cert,http-title,whois,udp-proto-scanner $host
                ;;
            6)
                break
                ;;
            *)
                echo "Opción inválida"
                ;;
        esac
    done
}

function analyze_api() {
    # Pedir la URL de la API al usuario
    echo "Por favor, introduce la URL del punto final de la API:"
    read url

    # Obtener la respuesta de la API
    response=$(curl -s "$url")

    # Obtener los códigos de respuesta HTTP
    http_codes=$(echo "$response" | grep -oP 'HTTP/\d\.\d \K\d{3}')

    # Obtener los encabezados de la respuesta
    headers=$(echo "$response" | grep -oP '^[A-Za-z-]+:.*')

    # Obtener el cuerpo de la respuesta en formato JSON
    json_body=$(echo "$response" | jq '.')

    # Obtener el tipo de contenido de la respuesta
    content_type=$(echo "$headers" | grep -i 'content-type:' | awk '{print $2}')

C    # Imprimir los resultados
    echo "Códigos de respuesta HTTP: $http_codes"
    echo "Encabezados de respuesta:"
    echo "$headers"
    echo "Cuerpo de respuesta en formato JSON:"
    echo "$json_body"
    echo "Tipo de contenido de la respuesta: $content_type"
}


function interactive_lsof() {
  read -p "Ingrese el puerto o el nombre del proceso a buscar: " query
  lsof -i ":$query" -nP | grep -i "$query"
  read -p "Desea buscar por una extensión de archivo? (S/N): " ext_search
  if [ "$ext_search" == "S" ] || [ "$ext_search" == "s" ]; then
    read -p "Ingrese la extensión de archivo a buscar: " extension
    read -p "Ingrese la cantidad mínima de repeticiones de la cadena a buscar: " repeticiones
    read -p "Ingrese el tamaño mínimo de archivo a buscar (en bytes): " min_size
    echo "Búsqueda de archivos con la extensión .$extension, repeticiones mínimas de $repeticiones y tamaño mínimo de archivo de $min_size bytes:"
    find / -type f -name "*.$extension" -size "+${min_size}c" -print0 | xargs -0 grep -inH "$query" | awk -F: '{if ($2 >= '$repeticiones') print}'
  fi
  read -p "Desea buscar por tareas cron y jobs? (S/N): " cron_search
  if [ "$cron_search" == "S" ] || [ "$cron_search" == "s" ]; then
    echo "Listado de tareas cron y jobs activos:"
    crontab -l
    echo "Listado de procesos en segundo plano:"
    ps -ef | grep -v grep | grep -v interactive_lsof
    echo "Listado de procesos ejecutándose actualmente:"
    top -b -n 1 | head -n 20
  fi
}



#WhichSystem

function which_system() {
  if [ $# -ne 1 ]; then
    echo "[!] Uso: $0 <direccion-ip>"
    return 1
  fi

  local ip_address=$1
  local ttl=$(ping -c 1 $ip_address | grep "ttl=" | sed 's/.*ttl=\([0-9]*\).*/\1/')

  if [ -z "$ttl" ]; then
    echo "Not Found"
    return 1
  fi

  if [ $ttl -ge 0 ] && [ $ttl -le 64 ]; then
    echo "$ip_address (ttl -> $ttl): Linux"
  elif [ $ttl -ge 65 ] && [ $ttl -le 128 ]; then
    echo "$ip_address (ttl -> $ttl): Windows"
  else
    echo "Not Found"
  fi
}


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


#Discord

function Discord() {

     /home/imahian/.Discord/Discord
}


function mkt() {
    mkdir nmap exploits content
}

function VPN() {
    if [ ! -f /home/imahian/HTB/imahian.ovpn ]; then
        echo "Error: VPN configuration file not found."
        return 1
    fi
    sudo openvpn /home/imahian/HTB/imahian.ovpn
}


function search_process() {
    # Ask user for process name
    read -p "Enter process name: " process_name

    # Check if process name is provided
    if [ -z "$process_name" ]; then
        echo "No process name provided."
        return 1
    fi

    # Watch processes in real time
    watch "sudo ps aux | grep -i \"$process_name\""

    # Ask user for search criteria
    read -p "Enter search criteria press Enter to skip: " search_criteria

    # Check if search criteria is provided
    if [ -z "$search_criteria" ]; then
        return 0
    fi

    # Filter processes by search criteria
    watch "sudo ps aux | grep -i \"$process_name\" | grep -i \"$search_criteria\""
}

function search_port() {
    if [ $# -ne 1 ]; then
        echo "Usage: search_port <port>"
        return 1
    fi
    
    echo "Process using port $1: "
    ps -p $(sudo netstat -tnlp | grep -i ":$1" | awk '{print $7}' | sed 's|/.*||') -o cmd=
    echo "Connections on port $1:"
    sudo netstat -tn | grep -i ":$1" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr
}


function cpu_usage() {
    sudo ps aux --sort=-%cpu | head -n 6
}

function check_system() {
    sudo df -h
    sudo journalctl -p 3 -xb
    sudo apt-get update && sudo apt-get upgrade && sudo apt-get dist-upgrade && sudo apt-get autoremove
}

function backup_data() {
    sudo tar -czf backup.tar.gz /home/user/data
    sudo scp backup.tar.gz user@remote-server:/backups/
}


# Función para realizar un ping a una dirección IP y verificar si hay respuesta
function ping_host() {
    ping -c 1 "$1" >/dev/null && echo "Host $1 is active."
}

# Función para escanear la red local y buscar hosts activos
function ip_scan(){
    echo "|      IP Address |    OS Type |       MAC Address |              Company |             Hostname |           Open Ports |"
    echo "|-----------------|------------|-------------------|-----------------------|-----------------------|----------------------|"
    for ip in {1..255}; do
        if ping -c 1 -w 1 192.168.1.$ip > /dev/null; then
            os=$(sudo nmap -O 192.168.1.$ip | grep "Running" | awk '{print $2}')
            mac=$(sudo nmap -sn 192.168.1.$ip | awk '/MAC Address:/{print $3}')
            company=$(sudo grep -i "^${mac:0:8}" /usr/share/nmap/nmap-mac-prefixes | awk -F '\t' '{print $2}')
            hostname=$(sudo nmap -sL 192.168.1.$ip | awk '/hostname/{print substr($0,index($0,$2))}')
            open_ports=$(sudo nmap -sT -p- 192.168.1.$ip | grep "open" | awk -F '/' '{print $1}' | xargs | sed 's/ /,/g')
            printf "| %15s | %10s | %17s | %22s | %22s | %20s |\n" "192.168.1.$ip" "$os" "$mac" "$company" "$hostname" "$open_ports"
        fi
    done
}

# Función para buscar hosts activos en la red utilizando Nmap
function nmap_scan() {
    echo "Scanning network for active hosts using Nmap..."
    sudo nmap -sn 192.168.1.0/24 | grep "Nmap scan report" | awk '{print $5}' | sed 's/(//g' | sed 's/)//g' && echo "Scan complete."
}

function google_dorks() {
    echo "Bienvenido a la herramienta de Google Dorks"
    echo "¿Qué tipo de búsqueda desea realizar?"
    echo "1. Búsqueda de archivos con información sensible"
    echo "2. Búsqueda de directorios y archivos expuestos en servidores web"
    echo "3. Búsqueda de información de usuarios y contraseñas"
    read -p "Seleccione una opción: " opcion

    case $opcion in
        1)
            echo "Búsqueda de archivos con información sensible"
            echo "Ejemplos: passwd, shadow, db, credentials"
            read -p "Ingrese su consulta de búsqueda: " consulta
            resultado=$(curl -s "https://www.google.com/search?q=$consulta&num=100" | grep -Eo '(http|https)://[^/"]+' | grep -E '(\.sql|\.db|\.dbf|\.mdb|\.bak|\.lst|\.pwd|\.txt|\.ini|\.conf|\.swp|\.inc|\.old|\.log|\.ora|\.sql.gz|\.zip|\.tar|\.tar.gz|\.bak|\.backup)' | sort -u)
            echo "$resultado" | grep --color=always "$2"
            ;;
        2)
            echo "Búsqueda de directorios y archivos expuestos en servidores web"
            echo "Ejemplos: inurl:/wp-content/uploads/, intitle:index.of /private"
            read -p "Ingrese su consulta de búsqueda: " consulta
            resultado=$(curl -s "https://www.google.com/search?q=$consulta&num=100" | grep -Eo "(http|https)://[^/]+/[^\"]+" | grep -E "\.(txt|db|sql|bak|old|backup|zip|tar|gz)" | sort -u)
            echo "$resultado" | grep --color=always "$2"
            ;;
        3)
            echo "Búsqueda de información de usuarios y contraseñas"
            echo "Ejemplos: intext:\"username\" | intext:\"password\""
            read -p "Ingrese su consulta de búsqueda: " consulta
            resultado=$(curl -s "https://www.google.com/search?q=$consulta&num=100" | grep -Eo "(http|https)://[^/]+/[^\"]+" | grep -Ei "config|wp-config|conf|credentials|passwd|passwords" | sort -u)
            echo "$resultado" | grep --color=always "$2"
            ;;
        *)
            echo "Opción no válida"
            ;;
    esac
}


# Función para escanear los puertos de un host utilizando Nmap
function nmap_port_scan() {
    echo "Scanning ports of host $1 using Nmap..."
    sudo nmap -p- "$1" | grep open && echo "Scan complete."
}



# Función para capturar tráfico de red con Wireshark
function capture_traffic() {
    # Verificar si Wireshark está instalado
    if ! command -v wireshark >/dev/null 2>&1; then
        echo "Wireshark is not installed. Please install it and try again."
        return 1
    fi

    # Solicitar la interfaz de red a utilizar
    echo "Enter the name of the network interface to use e.g. eth0:"
    read interface

    # Mostrar mensaje de advertencia sobre la necesidad de permisos de root
    echo "Note: This tool requires root privileges to capture network traffic."

    # Solicitar confirmación del usuario antes de continuar
    read -p "Do you want to continue? y/n: " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "Aborting capture."
        return 1
    fi

    # Realizar la captura de tráfico
    echo "Starting capture on interface $interface. Press Ctrl+C to stop."
    sudo wireshark -i "$interface"
}

function check_internet() {
    wget -q --spider http://google.com

    if [ $? -eq 0 ]; then
        echo "Internet connection is active."
    else
        echo "Internet connection is not active."
    fi
}

function nessus_scan() {
    echo "Starting Nessus scan..."
    sudo /etc/init.d/nessusd start
    nessuscli scan new
    echo "Scan complete. Results can be found at /var/lib/nessus/"
}

function auto_switch_workspaces() {
    interval=$1 # intervalo de tiempo en segundos
    while true
    do
       sudo  wmctrl -s $(expr $(wmctrl -d | grep '*' | cut -d ' ' -f 1) % $(wmctrl -d | wc -l))
            sleep $interval
    done
}
function run_command_periodically() {
    command="$1" # el comando a ejecutar
    interval=$2 # intervalo de tiempo en segundos
    while true
    do
        $command
        sleep $interval
    done
}
function send_email_periodically() {
    recipient="$1" # el destinatario del correo electrónico
    subject="$2" # el asunto del correo electrónico
    message="$3" # el mensaje del correo electrónico
    interval=$4 # intervalo de tiempo en segundos
    while true
    do
        echo "$message" | mail -s "$subject" "$recipient"
        sleep $interval
    done
}


function scan_for_viruses() {
    file="$1" # el archivo a escanear
    sudo clamscan "$file" # utiliza el programa ClamAV para escanear el archivo en busca de virus
}

function block_ip() {
    ip="$1" # la dirección IP a bloquear
    iptables -A INPUT -s $ip -j DROP # utiliza iptables para bloquear la dirección IP
}

function monitor_system_logs() {
    echo "Enter the log file to monitor e.g /var/log/syslog: "
    read log_file

    if [ ! -f "$log_file" ]; then
        echo "File not found!"
        return 1
    fi

    echo "Enter the string to monitor e.g fail, error, warning: "
    read search_string

    echo "Monitoring $log_file for occurrences of '$search_string'..."

    tail -f "$log_file" | grep -i "$search_string"
}


# Después de agregar tus propias funciones, no olvides agregar la siguiente línea:
unset MAILCHECK



