#!/bin/bash

# COLORS

RED='\e[1;31m'
ORANGE='\e[1;33m'
GREEN='\e[1;32m'
CYAN='\e[1;36m'
WHITE='\e[1;37m'
BACKGROUND_BLACK='\e[40m'



function user_checks { # Checks current user
	echo -e "$CYAN\n---CHECKING CURRENT USER AND ITS PRIVILEGES...---\n$WHITE"
	id | grep --color -E "docker|adm|disk|lxc|lxd|sudo|$"
	PRIVS=$(sudo -l)
	if [ -z "$PRIVS" ]
	then
		echo -e "\nNo sudo rights or user password is required to check them..."
	else
		echo -e "$RED\nUser has sudo rights:\n\n$WHITE" 
		echo -e "$PRIVS" | grep --color -E " \*|env_keep\W*\+=.*LD_PRELOAD|env_keep\W*\+=.*LD_LIBRARY_PATH|env_keep\W*\+=.*BASH_ENV|env_keep\W*\+=.* ENV|[^a-zA-Z0-9]7z$|aa-exec$|[^a-zA-Z0-9]ab$|alpine$|ansible-playbook$|ansible-test$|aoss$|apache2$|apache2ctl$|apt-get$|[^a-zA-Z0-9]ar$|aria2c$|[^a-zA-Z0-9]arj$|[^a-zA-Z0-9]arp$|[^a-zA-Z0-9]as$|ascii-xfr$|ascii85$|[^a-zA-Z0-9]ash$|aspell$|[^a-zA-Z0-9]at$|atobm$|[^a-zA-Z0-9]aws$|base32$|base58$|base64$|basenc$|basez$|bash$|batcat$|[^a-zA-Z0-9]bc$|bconsole$|bpftrace$|bridge$|bundle$|busctl$|busybox$|byebug$|bzip2$|cabal$|cancel$|capsh$|[^a-zA-Z0-9]cat$|cdist$|certbot$|check_by_ssh$|check_cups$|check_log$|check_memory$|check_raid$|check_ssl_cert$|check_statusfile$|chmod$|choom$|chown$|chroot$|clamscan$|[^a-zA-Z0-9]cmp$|cobc$|column$|comm$|composer$|cowsay$|cowthink$|[^a-zA-Z0-9]cp$|cpan$|cpio$|cpulimit$|crash$|crontab$|[^a-zA-Z0-9]csh$|csplit$|csvtool$|[^a-zA-Z0-9]ctr$|cupsfilter$|curl$|[^a-zA-Z0-9]cut$|dash$|date$|[^a-zA-Z0-9]dc$|[^a-zA-Z0-9]dd$|debugfs$|dialog$|diff$|[^a-zA-Z0-9]dig$|distcc$|dmesg$|dmsetup$|[^a-zA-Z0-9]dnf$|doas$|docker$|dos2unix$|dosbox$|dotnet$|dpkg$|dstat$|dvips$|easy_install$|[^a-zA-Z0-9]eb$|[^a-zA-Z0-9]ed$|efax$|egrep$|elvish$|emacs$|enscript$|[^a-zA-Z0-9]env$|[^a-zA-Z0-9]eqn$|espeak$|[^a-zA-Z0-9]ex$|exiftool$|expand$|expect$|facter$|fail2ban-client$|fgrep$|file$|find$|finger$|fish$|flock$|[^a-zA-Z0-9]fmt$|fold$|fping$|[^a-zA-Z0-9]ftp$|gawk$|[^a-zA-Z0-9]gcc$|gcloud$|gcore$|[^a-zA-Z0-9]gdb$|[^a-zA-Z0-9]gem$|genie$|genisoimage$|[^a-zA-Z0-9]ghc$|ghci$|gimp$|ginsh$|[^a-zA-Z0-9]git$|[^a-zA-Z0-9]grc$|grep$|gtester$|gzip$|hashcat$|head$|hexdump$|highlight$|hping3$|iconv$|iftop$|install$|ionice$|[^a-zA-Z0-9]ip$|[^a-zA-Z0-9]irb$|ispell$|[^a-zA-Z0-9]jjs$|[^a-zA-Z0-9]joe$|join$|journalctl$|[^a-zA-Z0-9]jq$|jrunscript$|jtag$|julia$|knife$|ksshell$|[^a-zA-Z0-9]ksu$|kubectl$|latex$|latexmk$|ld.so$|ldconfig$|less$|lftp$|links$|[^a-zA-Z0-9]ln$|loginctl$|logrotate$|logsave$|look$|[^a-zA-Z0-9]lp$|ltrace$|[^a-zA-Z0-9]lua$|lualatex$|luatex$|lwp-download$|lwp-request$|mail$|make$|[^a-zA-Z0-9]man$|mawk$|minicom$|more$|mosquitto$|mount$|msfconsole$|ALL|*|$"
	fi

# Checks existing users / groups

	echo -e "$CYAN\n---CHECKING EXISTING USERS AND THEIR GROUPS...---\n$WHITE"

	USERS=$(grep --color -E "sh$" /etc/passwd | cut -d ":" -f 1)

	for user in $USERS; 
	do
  	  groups "$user"
	done

	echo -e "$CYAN\nConnected users :\n$WHITE"
	w && who

	echo -e "$CYAN\nHome repositories :\n$WHITE"
	ls -la /home
}

function fs_checks {
	echo -e "$CYAN\n---CHECKING MOUNTS,DISKS...---\n$WHITE"

	echo -e "$CYAN\nDisks :\n$WHITE"
	lsblk

	echo -e "$CYAN\nPrinters :\n$WHITE"
	lpstat

	echo -e "$CYAN\nMounted FS : \n$WHITE"
	df -h
	mount
	cat /etc/fstab | grep --color -iE 'pass|user|credential'


	echo -e "$CYAN\nUnmounted FS :\n$WHITE"
	cat /etc/fstab | grep --color -v "#" | column -t
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
	echo -e "$CYAN\nWritable files for $current_user :\n$WHITE"
	find / -perm -u+w -user $current_user 2>/dev/null | grep --color -vE "proc|run|sys"
	find / -perm -o+w 2>/dev/null | grep --color -vE "proc|run|sys"

	#GROUPS=($(id -nG))
	#for group in $GROUPS
	#do
	#	echo -e "Writable files for "$group"\n\n"
	#	find / -perm -g+w -group $group 2>/dev/null | grep --color -vE "proc|run|sys"
	#done
}

function netconf_checks {

	echo -e "$CYAN\n---CHECKING NETWORK CONFIGURATION...---\n$WHITE"
	echo -e "$CYAN\nSockets listening on 127.0.0.1 :\n$WHITE"
	ss -tulnp && netstat -tulnp | grep --color 127.0.0.1
	
	echo -e "$CYAN\nConfigured DNS :\n$WHITE"
	cat /etc/resolv.conf
	
	echo -e "$CYAN\nHosts file :\n$WHITE"
	cat /etc/hosts
	
	echo -e "$CYAN\nARP Table :\n$WHITE"
	arp -a
	
	echo -e "$CYAN\nRouting Table :\n$WHITE"
	netstat -rn
}

function process_checks {

	echo -e "$CYAN\n---CHECKING RUNNING PROCESSES...---\n$WHITE"
	ps -aux
	echo -e "$ORANGE\nDon't forget to launch pspy too with ./pspy64 -pf -i 1000 | grep --color 'UID=0' !"
}

function cron_checks {

	echo -e "$CYAN\n---CHECKING CRON JOBS...---\n$WHITE"
	ls -la /etc/cron.*/ /var/spool/cron/crontabs 2>/dev/null
	cat /etc/crontab
}

function programs_checks {

	echo -e "$CYAN\n---CHECKING PROGRAMS...---\n$WHITE"
	
	sudo=$(sudo -V | head -n1)
	if [ -z sudo ]
	then
		echo -e "Sudo not installed\n"
	else
		echo -e "$CYAN\nSudo Version :\n$WHITE"	
		echo -e "$sudo" | grep --color -E "[01].[012345678].[0-9]+|1.9.[01234][^0-9]|1.9.[01234]$|1.9.5p1|1\.9\.[6-9]|1\.9\.1[0-7]"
	fi
	
	screen=$(screen --version)
	if [ -z screen ]
	then
		echo -e "Screen not installed\n"
	else
		echo -e "$CYAN\nScreen Version :\n$WHITE"
		echo -e "$screen"
	fi
	
	polkit=$(pkexec --version | head -n1 && apt list --installed | grep --color policykit)
	if [ -z polkit ]
	then
		echo -e "Polkit not installed\n"
	else
		echo -e "$CYAN\nPolkit Version :\n$WHITE"
		echo -e "$polkit" | grep --color -E "0.105|$"
	fi
	
	
	
	echo -e "$CYAN\nGTFOBINS :\n$WHITE"
	GTFOBINS=$(curl -s https://gtfobins.org | grep --color gtfobin-name | cut -d "\"" -f 2 | tr '\n' '|' )
	ls -la `find / -perm /u=s,g=s -type f 2>/dev/null` | grep --color -E "$GTFOBINS"
}

function os_infos {

	echo -e "$CYAN\n---CHECKING OS INFOS...---\n$WHITE"
	
	echo -e "$CYAN\nOS Version :\n$WHITE"
	cat /etc/os-release

	echo -e "$CYAN\nKernel Version :\n$WHITE"
	uname -a
	cat /proc/version
	
	echo -e "$CYAN\nCPU infos :\n$WHITE"
	lscpu
}

user_checks
fs_checks
files_checks
netconf_checks
process_checks
os_infos
cron_checks
programs_checks
