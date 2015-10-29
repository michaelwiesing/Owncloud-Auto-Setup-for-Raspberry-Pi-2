#!/bin/bash

############################################################################
#
#    Copyright (C) 2015 Michael Wiesing
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
############################################################################

echo "--------------------------------------"
echo "|                                    |"
echo "| A script for automated owncloud    |"
echo "| installation on raspbian or debian |"
echo "| in version 8 alias jessie with some|"
echo "| additional features.               |"
echo "|                                    |"
echo "| Copyright (C) 2015 Michael Wiesing |"
echo "|                                    |"
echo "--------------------------------------"

#Some bash script optimization for robustness (More information: www.davidpashley.com/articles/writing-robust-shell-scripts/)
#Break if the script uses unset variables
set -o nounset
#Break if a command has a non-true return value
set -o errexit

echo_info () {
	echo "--------------------------------------"
	echo "| INFO: $1"
	echo "--------------------------------------"
}

echo_error () {
	echo "--------------------------------------"
	echo "| ERROR: $1"
	echo "--------------------------------------"
}

is_installed () {
	#Check if a package is installed (More information: https://askubuntu.com/questions/319307/reliably-check-if-a-package-is-installed-or-not)
	if dpkg --get-selections | grep -q "^$1[[:space:]]*install$" >/dev/null; then
		echo_error "$1 is already installed"
		exit 1
	fi
}

check_not_installed () {

	echo_info "Check if some package is already installed. If this is the case the script stops because it could not be performed without risc."

	is_installed apache2
	is_installed mysql-server-5.5
	is_installed owncloud
	is_installed fail2ban 

}

check_root () {
	if [ "$(id -u)" != "0" ]; then
		echo_error "The script must be called as root user!"
		exit 1
	fi
}

install_owncloud () {

	cd /tmp

	#Automatic installation of owncloud (More information: https://software.opensuse.org/download/package?project=isv:ownCloud:community&package=owncloud)

	echo_info "Add package repository"

	echo 'deb http://download.owncloud.org/download/repositories/8.2/Debian_8.0/ /' >> /etc/apt/sources.list.d/owncloud.list

	wget -nv https://download.owncloud.org/download/repositories/8.2/Debian_8.0/Release.key -O Release.key
	apt-key add - < Release.key  
	rm Release.key	
	
	echo_info "Install owncloud"

	#Because a dependency the package mysql-server-5.5 is installed too. During the installation a prompt ask for the root password. The next lines set it with the value of the variable. (More information: http://www.microhowto.info/howto/perform_an_unattended_installation_of_a_debian_package.html)
	echo "mysql-server-5.5 mysql-server/root_password password $mysqlRootPw" | debconf-set-selections
	echo "mysql-server-5.5 mysql-server/root_password_again password $mysqlRootPw" | debconf-set-selections

	apt-get update
	apt-get --assume-yes install owncloud

}

create_mysql_db () {

	echo_info "Create mysql database for owncloud"

	#Create a new database and user for owncloud (More information: http://www.bluepiccadilly.com/2011/12/creating-mysql-database-and-user-command-line-and-bash-script-automate-process)
	mysql=`which mysql`
	  
	Q1="CREATE DATABASE IF NOT EXISTS $ocDb;"
	Q2="GRANT USAGE ON *.* TO $ocDbUser@localhost IDENTIFIED BY '$ocDbUserPw';"
	Q3="GRANT ALL PRIVILEGES ON $ocDb.* TO $ocDbUser@localhost;"
	Q4="FLUSH PRIVILEGES;"
	SQL="${Q1}${Q2}${Q3}${Q4}"
	 
	$mysql -uroot -p$mysqlRootPw -e "$SQL"

}

patch_apache_filesize () {

	echo_info "Patch apache configuration"
	
	#Patch filesize in the htaccess (More Information: http://blog.webernetz.net/2015/07/15/yet-another-owncloud-installation-guide/)
	sed -i "s/php_value upload_max_filesize .*/php_value upload_max_filesize $maxFileSize/" /var/www/owncloud/.htaccess
	sed -i "s/php_value post_max_size .*/php_value post_max_size $maxFileSize/" /var/www/owncloud/.htaccess
	sed -i "s/php_value memory_limit .*/php_value memory_limit $maxFileSize/" /var/www/owncloud/.htaccess
	
	/etc/init.d/apache2 restart
}

configure_owncloud () {

	echo_info "Configure owncloud"
	
	#The data dir should not be under /var/www for security reasons, so the dir must be created (More information: https://doc.owncloud.org/server/8.1/admin_manual/configuration_server/harden_server.html)
	mkdir $ocDataDir
	chown -R ${htuser}:${htgroup} ${ocDataDir}/

	#Use the cli for first configuration (More information: https://doc.owncloud.org/server/8.1/admin_manual/installation/command_line_installation.html)
	cd /var/www/owncloud
	sudo -u $htuser php occ maintenance:install --database "mysql" --database-name "$ocDb"  --database-user "$ocDbUser" --database-pass "$ocDbUserPw" --admin-user "$ocAdminUser" --admin-pass "$ocAdminUserPw" --data-dir "$ocDataDir"
	
		#Add the hostname and ip to the trusted domains, so that it could be reached from outside (More Information: https://doc.owncloud.org/server/8.1/admin_manual/installation/installation_wizard.html?highlight=trusted_domains#label-trusted-domains)
	sed -i "/.*0 => 'localhost',/a \\    1 => '$hostname',\n    2 => '$ip'," /var/www/owncloud/config/config.php

	/etc/init.d/apache2 restart

}

install_fail2ban () {

	echo_info "Install fail2ban"
	
	apt-get --assume-yes install fail2ban
	
	#First configure the owncloud logfile
	logFileMasked=$(echo $logFile | sed 's/\//\\\//g')
	logTimezoneMasked=$(echo $logTimeZone | sed 's/\//\\\//g')
	sed -i "s/  'logtimezone' => 'UTC',/  'logtimezone' => '$logTimezoneMasked',\n  'logfile' => '$logFileMasked',\n  'loglevel' => '2',/" /var/www/owncloud/config/config.php

	touch $logFile
	chown ${htuser}:${htgroup} $logFile

	#Now configure fail2ban (More Information: http://www.rojtberg.net/711/secure-owncloud-server/, https://got-tty.org/archives/owncloud-6-sicherheit-durch-fail2ban.html)
	echo -e "[Definition]\nfailregex={\"app\":\"core\",\"message\":\"Login failed: user '.*' , wrong password, IP:<HOST>\",\"level\":2,\"time\":\".*\"}\n          {\"app\":\"core\",\"message\":\"Login failed: '.*' \(Remote IP: '<HOST>', X-Forwarded-For: '.*'\)\",\"level\":2,\"time\":\".*\"}\n          {\"reqId\":\".*\",\"remoteAddr\":\"<HOST>\",\"app\":\"core\",\"message\":\"Login failed: .*\",\"level\":2,\"time\":\".*\"}" > /etc/fail2ban/filter.d/owncloud.conf

	echo -e "[owncloud]\nenabled  = true\nfilter   = owncloud\nport     = http,https\nmaxretry = $maxRetry\nlogpath  = $logFile" >> /etc/fail2ban/jail.local

	/etc/init.d/fail2ban restart
}

enable_apache_ssl () {
	
	echo_info "Enable and compel apache ssl with default self-signed certifiacte of debian"

	#Uses the default self-signed certificate of debian (More information: https://doc.owncloud.org/server/8.1/admin_manual/installation/source_installation.html#enabling-ssl)
	a2enmod ssl
	a2ensite default-ssl
	
	#Force https for every connection (More information: https://doc.owncloud.org/server/8.1/admin_manual/configuration_server/harden_server.html)
	a2enmod headers
	sed -i "/.*<VirtualHost.*/a \\\tServerName $hostname\n\tRedirect permanent \/ https:\/\/$hostname\/" /etc/apache2/sites-available/000-default.conf
	sed -i "/.*<VirtualHost.*/a \\\t\tServerName $hostname\n\t\tHeader always add Strict-Transport-Security \"max-age=15768000\"" /etc/apache2/sites-available/default-ssl.conf
	
	/etc/init.d/apache2 restart
}

enable_apc_cache () {

	echo_info "Enable apc cache"
	#Install and configure apcu (More information: https://owncloud.org/blog/making-owncloud-faster-through-caching/)
	apt-get --assume-yes install php-apc
	sed -i "s/);/  'memcache.local' => '\\\OC\\\Memcache\\\APCu',\n);/" /var/www/owncloud/config/config.php
	
	/etc/init.d/apache2 restart
}

#Read in the variables in an interacive mode. Too make it a little more comfortable, the following functions need to be defined.

#Read a value and set the default value as input (More Information: http://stackoverflow.com/questions/2642585/read-a-variable-in-bash-with-a-default-value)
read_value () {
	unset value
	read -e -i $1 value
}

#Hide the input and mask it with stars (More Information: http://stackoverflow.com/questions/1923435/how-do-i-echo-stars-when-reading-password-with-read) (Part of the read_pw function)
read_pw_loop_masked () {
	unset password
	while IFS= read -p "$prompt" -r -s -n 1 char
	do
    	if [[ $char == $'\0' ]]
	    then
    	    break
    	fi
	    prompt='*'
	    password+="$char"
	done
	echo
}

#Ask for the password two times (Part of the read_pw function)
read_pw_loop_compare () {
	prompt="Enter Password:"
	read_pw_loop_masked
	password1=$password
	prompt="Reenter Password:"
	read_pw_loop_masked
	password2=$password
}

#Loop the password question until the two values match (Part of the read_pw function)
read_pw_loop () {
	read_pw_loop_compare
	while [ "$password1" != "$password2" ] ; do
		echo "Please retype, because the passwords did not match."
		read_pw_loop_compare	
	done
	password=$password1
}

#Main function for reading a password
read_pw () {
	echo $*
	read_pw_loop
	
}

ask_for_values () {
	echo_info "The script now ask for some values that are necessary for the installation."
	#You can customize the default values of the variables here or set a static value

	#Hostname and IP (the command retrieve this information automatically in the case that only the standard ethernet interface is installed)
	hostname=`hostname`
	echo "Please enter the hostname (The automatically indentified value is filled in, but you can easily change it if it is wrong.):"
	read_value $hostname
	hostname=$value
	ip=`hostname -I`
	echo "Please enter the ip of the outside interface (The automatically indentified value is filled in, but you can easily change it if it is wrong.):"
	read_value $ip
	ip=$value

	#Mysql configuration
	read_pw "Please enter a password for the root user of mysql:"
	mysqlRootPw=$password

	echo "Please enter the name of the mysql database for owncloud (The default value is filled in, but you can easily change it.):"
	read_value owncloud
	ocDb=$value

	echo "Please enter the name of the mysql user for owncloud (The default value is filled in, but you can easily change it.):"
	read_value owncloud
	ocDbUser=$value

	read_pw "Please enter a password for the owncloud user of mysql:"
	ocDbUserPw=$password

	#Apache2 configuration
	echo "Please enter the maximal size of files that could be uploaded to owncloud (The default value is filled in, but you can easily change it.):"
	read_value 1024M
	maxFileSize=$value
	#Typically user and group filled static
	htuser='www-data'
	htgroup='www-data'

	#Owncloud configuration

	echo "Please enter the name of the owncloud administrator(The default value is filled in, but you can easily change it.):"
	read_value admin
	ocAdminUser=$value

	read_pw "Please enter a password for the owncloud administrator:"
	ocAdminUserPw=$password

	echo "Please enter the path to the folder for files of owncloud (The default value is filled in, but you can easily change it.):"
	read_value /home/owncloud
	ocDataDir=$value

	#Fail2Ban
	logTimeZone=`cat /etc/timezone`
	echo "Please enter the time zone for the owncloud log (The default value is filled in, but you can easily change it.):"
	read_value $logTimeZone
	logTimeZone=$value

	echo "Please enter the path where owncloud log should be saved (The default value is filled in, but you can easily change it.):"
	read_value /var/log/owncloud.log
	logFile=$value

	echo "Please enter the max fails until fail2ban ban an ip (The default value is filled in, but you can easily change it.):"
	read_value 3
	maxRetry=$value

}

generate_self_signed_certificate () {

	echo_info "The script now generate a self signed certificate with a self created ca. For it the script ask for many values. The most necessary you can fill with a dot if you do not have a valid value. The 'extra' attributes you could skip with enter. Only the pass phrase for own-ca.key and the common name are important. The first value is the password for your ca, please type in a strong password and take a note of it. You will need it at least some seconds later. The common name must befit the hostname and you must type it in two times."

	#Generate a self signed certificate with a self created ca (More Information: https://thomas-leister.de/internet/eine-eigene-openssl-ca-erstellen-und-self-signed-certe-ausstellen/)
	# This was necessary because otherwise Apps like DAVdroid didn't work with the owncloud (More Information: https://davdroid.bitfire.at/faq/entry/importing-a-certificate)

	#Create a new ca
	mkdir /etc/ssl/ownca/
	cd /etc/ssl/ownca/
	openssl genrsa -aes256 -out own-ca.key 2048
	#Create the root certificate that is valid for 10 years
	openssl req -x509 -new -nodes -extensions v3_ca -key own-ca.key -days 3650 -out own-ca-root.pem -sha512
	#Create a client certificate that is valid for 10 years and sign it
	openssl genrsa -out self-signed-cert.key 4096
	openssl req -new -key self-signed-cert.key -out self-signed-cert.csr -sha512
	openssl x509 -req -in self-signed-cert.csr -CA own-ca-root.pem -CAkey own-ca.key -CAcreateserial -out self-signed-cert.pem -days 3650 -sha512
	rm self-signed-cert.csr
	mv ./self-signed-cert.pem ../certs
	mv ./self-signed-cert.key ../private
	mv ./own-ca-root.pem ../certs
	
}

install_self_signed_certificate () {
	sed -i "s/		SSLCertificateFile	\/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/		SSLCertificateFile	\/etc\/ssl\/certs\/self-signed-cert.pem/" /etc/apache2/sites-available/default-ssl.conf
	sed -i "s/		SSLCertificateKeyFile \/etc\/ssl\/private\/ssl-cert-snakeoil.key/		SSLCertificateKeyFile \/etc\/ssl\/private\/self-signed-cert.key/" /etc/apache2/sites-available/default-ssl.conf
	sed -i "s/		#SSLCertificateChainFile \/etc\/apache2\/ssl.crt\/server-ca.crt/		SSLCertificateChainFile \/etc\/ssl\/certs\/own-ca-root.pem/" /etc/apache2/sites-available/default-ssl.conf
	/etc/init.d/apache2 restart
}

#You can customize the called functions here (you are responsible for looking for dependencies between them)
check_root
check_not_installed
ask_for_values
generate_self_signed_certificate
echo_info "Now the unattended part of the setup is started."
install_owncloud
create_mysql_db
patch_apache_filesize
configure_owncloud
install_fail2ban
enable_apache_ssl
enable_apc_cache
install_self_signed_certificate

echo_info "FINISH"
