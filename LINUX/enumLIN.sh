#!/bin/bash

# COLORS

RED='\e[31m'
ORANGE='\e[33m'
GREEN='\e[32m'
CYAN='\e[1;36m'
WHITE='\e[37m'
BACKGROUND_BLACK='\e[40m'



function user_checks { # Checks current user
	echo -e "$CYAN\n---CHECKING CURRENT USER AND ITS PRIVILEGES...---\n$WHITE"
	USER=$(id)
	echo -e "$USER"
	PRIVS=$(sudo -l)
	if [ -z "$PRIVS" ]
	then
		echo -e "\nNo sudo rights or user password is required to check them..."
	else
		echo -e "$RED\nUser has sudo rights:\n\n $PRIVS"
	fi

# Checks existing users / groups

	echo -e "$CYAN\n---CHECKING EXISTING USERS AND THEIR GROUPS...---\n$WHITE"

	USERS=$(grep -E "sh$" /etc/passwd | cut -d ":" -f 1)
	HOME=$(ls -la /home)
	CONNECTED_USERS=$(w && who)

	for user in $USERS; 
	do
  	  groups "$user"
	done

	echo -e "\nConnected users : \n$CONNECTED_USERS"

	echo -e "\nHome repositories : \n$HOME\n"
}

function fs_checks {
	echo -e "$CYAN\n---CHECKING MOUNTS,DISKS...---\n$WHITE"

	echo -e "\nDisks :\n"
	lsblk

	echo -e "\nPrinters :\n"
	lpstat

	echo -e "\nMounted FS : \n"
	df -h
	mount
	cat /etc/fstab | grep -iE 'pass|user|credential'


	echo -e "\nUnmounted FS :\n"
	cat /etc/fstab | grep -v "#" | column -t
}


function files_checks {

	echo -e "$CYAN\n---CHECKING HISTORY FILES...---\n$WHITE"
	HISTORY=$(find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null)
	if [ -z "$HISTORY" ]
	then
		echo -e "No history files found..."
	else
		echo -e "$RED\nHistory files found :\n\n $HISTORY"
	fi
	
	# Checks writable files for user

	echo -e "$CYAN\n---CHECKING WRITABLE FILES FOR CURRENT USER AND ITS GROUPS...---\n$WHITE"

	current_user=$(whoami)
	echo -e "Writable files for $current_user :\n"
	find / -perm -u+w -user $current_user 2>/dev/null | grep -vE "proc|run|sys"
	find / -perm -o+w 2>/dev/null | grep -vE "proc|run|sys"

	#GROUPS=($(id -nG))
	#for group in $GROUPS
	#do
	#	echo -e "Writable files for "$group"\n\n"
	#	find / -perm -g+w -group $group 2>/dev/null | grep -vE "proc|run|sys"
	#done
}

function netconf_checks {

	echo -e "$CYAN\n---CHECKING NETWORK CONFIGURATION...---\n$WHITE"
	echo -e "\nSockets listening on 127.0.0.1 :\n"
	ss -tulnp && netstat -tulnp | grep 127.0.0.1
	
	echo -e "\nConfigured DNS :\n"
	cat /etc/resolv.conf
	
	echo -e "\nHosts file :\n"
	cat /etc/hosts
	
	echo -e "\nARP Table :\n"
	arp -a
	
	echo -e "\nRouting Table :\n"
	netstat -rn
}

function cron_checks {

	echo -e "$CYAN\n---CHECKING CRON JOBS...---\n$WHITE"
	ls -la /etc/cron.*/ /var/spool/cron/crontabs 2>/dev/null
	cat /etc/crontab
}

function process_checks {

	echo -e "$CYAN\n---CHECKING RUNNING PROCESSES...---\n$WHITE"
	ps -aux
	echo -e "$ORANGE\nDon't forget to launch pspy too with ./pspy64 -pf -i 1000 | grep 'UID=0' !"
}

function os_infos {

	echo -e "$CYAN\n---CHECKING OS INFOS...---\n$WHITE"
	
	echo -e "\nOS Version :\n"
	cat /etc/os-release

	echo -e "\nKernel Version :\n"
	uname -a
	cat /proc/version
	
	echo -e "$WHITE\nCPU infos :\n"
	lscpu
}

user_checks
fs_checks
files_checks
netconf_checks
cron_checks
process_checks
os_infos
