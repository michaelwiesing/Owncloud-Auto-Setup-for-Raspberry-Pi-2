# Owncloud-Auto-Setup-for-Raspberry-Pi-2

A script for automated owncloud installation on raspbian or debian in version 8 alias jessie with some additional features.

The script asks for the necessary values at the start. After that it installs owncloud automatically. Among others the following steps are executed:
- install owncloud by adding the official repository for debian and choose the package
- install mysql and configure it for owncloud
- install apache 2 as webserver
- configure the webserver to use ssl with a self signed certificate
- install fail2ban and configure it for owncloud
- accelerate owncloud with the caching mechanism apcu

More information is available at my blog under http://wiesing.net/index.php/2015/08/18/installation-von-owncloud-auf-raspberry-2-automatisieren/ (only in german).
