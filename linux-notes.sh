# ALL LINUX BABY
# Erwyne John M. Santos
#----------------------------------------------------------------------------------------------------------------------------------------------

# TERMINAL SHORTCUTS FOR SPEED

sudo !! - re-run previous command with 'sudo' prepended
ctrl-k, ctrl-u, ctrl-w, ctrl-y - cutting and pasting text in the command line
use 'less +F' to view logfiles, instead of 'tail' (ctrl-c, shift-f, q to quit)
ctrl-x-e - continue editing your current shell line in a text editor (uses $EDITOR)
alt-. - paste previous argument (useful for running multiple commands on the same resource)
reset - resets/unborks your terminal
ctrl-r - browse through histroy
!$ - repeat previous directory used from the prev command
alt-f, alt-b - Move forward or back one word
#----------------------------------------------------------------------------------------------------------------------------------------------

# Backup script 

#!/bin/bash
backup=/mybackup/etc-$(date +%Y-%m-%d).tgz	# variable 'backup'
tar -cvf $backup /etc 						          # backsup /etc to /mybackup/etc/-$(date +%Y-%m-%d).tgz

# Append date to filename: filename-"`date +"%Y-%m-%d"`".log
#----------------------------------------------------------------------------------------------------------------------------------------------

# Only one instance of script is running
#!/usr/bin/env bash

if ! mkdir /tmp/abc.lock; then
    printf "Failed to acquire lock.\n" >&2
    exit 1
fi
trap 'rm -rf /tmp/abc.lock' EXIT  # remove the lockdir on exit

# rest of script ...

# Source: https://askubuntu.com/questions/157779/how-to-determine-whether-a-process-is-running-or-not-and-make-use-it-to-make-a-c
#----------------------------------------------------------------------------------------------------------------------------------------------

# Remove the lock directory
function cleanup {
    if rmdir $LOCKDIR; then
        echo "Finished"
    else
        echo "Failed to remove lock directory '$LOCKDIR'"
        exit 1
    fi
}

if mkdir $LOCKDIR; then
    #Ensure that if we "grabbed a lock", we release it
    #Works for SIGTERM and SIGINT(Ctrl-C)
    trap "cleanup" EXIT

    echo "Acquired lock, running"

    # Processing starts here
else
    echo "Could not create lock directory '$LOCKDIR'"
    exit 1
fi

# Source: https://unix.stackexchange.com/questions/48505/how-to-make-sure-only-one-instance-of-a-bash-script-runs
#----------------------------------------------------------------------------------------------------------------------------------------------

# Script to determine a process is running or not
#!/bin/bash
# Check if gedit is running
# -x flag only match processes whose name (or command line if -f is
# specified) exactly match the pattern. 

if pgrep -x "gedit" > /dev/null
then
    echo "Running"
else
    echo "Stopped"
fi
#----------------------------------------------------------------------------------------------------------------------------------------------

# While loop
#!/bin/bash
n=1

while [ $n -le 10 ]
do
	echo "$n"
	(( ++n ))
done
#----------------------------------------------------------------------------------------------------------------------------------------------

# For Loop
for server in ${server_list[*]};
do
echo "$server"
done
#----------------------------------------------------------------------------------------------------------------------------------------------

# Function
#!/bin/bash

test_shadow(){
	if [ -e /etc/shadow ];
	then
		echo "It exists"
	else
		echo "File does not exist"
}

test_passwd(){
	if [ -e /etc/passwd ];
	then
		echo "It exists"
	else
		echo "File does not exist"
}

test_shadow
test_passwd
#----------------------------------------------------------------------------------------------------------------------------------------------

# Scripts with parameters / Positional Parameters
#!/bin/bash
echo "the $1 eats a $2 every time there is a $3"
echo "bye:-)"

or

$ cat myscript
#!/bin/bash
echo "First arg: $1"
echo "Second arg: $2"
$ ./myscript hello world
First arg: hello
Second arg: world
#----------------------------------------------------------------------------------------------------------------------------------------------

# Shell Script to add user and password to Linux

#!/bin/bash
# Am i Root user?
if [ $(id -u) -eq 0 ]; then
	read -p "Enter username : " username
	read -s -p "Enter password : " password
	egrep "^$username" /etc/passwd >/dev/null
	if [ $? -eq 0 ]; then
		echo "$username exists!"
		exit 1
	else
		pass=$(perl -e 'print crypt($ARGV[0], "password")' $password)
		useradd -m -p "$pass" "$username"
		[ $? -eq 0 ] && echo "User has been added to system!" || echo "Failed to add a user!"
	fi
else
	echo "Only root may add a user to the system."
	exit 2
fi

# Reference: https://www.cyberciti.biz/tips/howto-write-shell-script-to-add-user.html
#----------------------------------------------------------------------------------------------------------------------------------------------

#------------------------------ Monitoring Script for filesystem on servers (Globe Project) (OUTDATED) ------------------------------

ON THE MANAGEMENT/MASTER SERVERS: (dpastgmo,dpamo)
# /home/teradata/filesystemcheck/getfilesystemchecks.sh
#!/bin/bash

server_list=(dpastgespkwik01 dpastgespkwik02)
rm /home/teradata/filesystemcheck/received/*

for server in ${server_list[*]};
do
scp teradata@$server:/home/teradata/filesystemcheck/output/* /home/teradata/filesystemcheck/received/
done

cd /home/teradata/filesystemcheck/received/;tail -n +1 * > /home/teradata/filesystemcheck/compiled/STG-servers-FS-util-"`date +"%Y-%m-%d"`".log

echo "/ filesystem util of servers that breached => 60%" | mailx -v -r STG_FS_util_notif@globe.com.ph -s "STG / FS util as of  `date '+%Y-%m-%d %H:%M:%S'`" -a /home/teradata/filesystemcheck/compiled/* "zecvista@globe.com.ph,zemsantos@globe.com.ph,zrtangpus@globe.com.ph,zgqtorres@globe.com.ph,zhcvenal@globe.com.ph"


ON THE CLIENT SERVERS: (dpastgespkwik01 dpastgespkwik02) - Version 1
# /home/teradata/filesystemcheck/filesystemcheck.sh
#!/bin/bash
#
if [ $(df / --output=pcent | awk -F '%' 'NR==2{print $1}') -ge 60 ] ;
then
        echo "/ FS util is => 60%";
        rm /home/teradata/filesystemcheck/output/*;
        find / -xdev -type f -exec du -sh {} ';' | sort -rh | head -50 > /home/teradata/filesystemcheck/output/STG-$HOSTNAME-util-`date '+%Y-%m-%d_%H:%M:%S'`;
        chown teradata.teradata /home/teradata/filesystemcheck/output/*;
fi;

ON THE CLIENT SERVERS: (dpastgespkwik01 dpastgespkwik02) - Version 2
# /home/teradata/filesystemcheck/filesystemcheck.sh
#!/bin/bash

rm_find(){
if [ $(df / --output=pcent | awk -F '%' 'NR==2{print $1}') -ge 80 ] ;
then
        echo "/ FS util is => 80%";
        echo "Running checker now"
        rm /home/teradata/filesystemcheck/output/*;
        find / -xdev -type f -exec du -sh {} ';' | sort -rh | head -50 > /home/teradata/filesystemcheck/output/STG-$HOSTNAME-util-`date '+%Y-%m-%d_%H:%M:%S'`.log;
        chown teradata.admin /home/teradata/filesystemcheck/output/*;
fi;
}

if pgrep -x "find" > /dev/null
then
	echo "Already running, waiting next 5 minutes"
	return 0
else
	echo "Stopped, running now. Please wait to finish.."
	rm_find
	echo "Done. Result stored in /home/teradata/filesystemcheck/output/"
return 0

NOTE: MAKE SURE ALL FILES AND DIRECTORIES AND SUB DIRECTORIES /home/teradata/filesystemcheck/ ARE CHOWNED TO teradata.teradata
NOTE: ONLY filesystemcheck.sh HAS TO BE OWNED AND RUN BY ROOT IN ORDER FOR IT TO CHECK ROOT DIRECTORIES AND DIRS/FILES NOT OWNED BY teradata
NOTE: CRONTAB THE filesystemcheck.sh ON THE CLIENT SERVERS EVERY 5 MINUTES
#----------------------------------------------------------------------------------------------------------------------------------------------

Filesystem checker bash script template
#!/bin/bash
rm_find(){
        if [ $(df /init --output=pcent | awk -F '%' 'NR==2{print $1}') -ge 50 ] ;
        then
        echo "Running checker now";
        rm /home/master/scripts/df/output/*;
        find / -xdev -type f -exec du -sh {} ';' | sort -rh | head -50 > /home/master/scripts/df/output/STG-$HOSTNAME-util-`date '+%Y-%m-%d_%H:%M:%S'`.log;
        chown ej.admin /home/master/scripts/df/output/*;
        fi;
}

scp_mail(){
scp  /home/master/scripts/df/output/* ej@192.168.50.11:/home/ej/scripts/df/received/
#xmail
}

rm_files(){
rm /home/master/scripts/df/output/*
ssh ej@192.168.50.11 'rm /home/ej/scripts/df/received/*; rm /home/ej/scripts/df/compiled/*'
}

if pgrep -x "find" > /dev/null
then
        echo "Already running, waiting next 5 minutes"
else
        echo "Stopped, running now. Please wait to finish.."
        rm_find
        scp_mail
        rm_files
fi
#----------------------------------------------------------------------------------------------------------------------------------------------

# Updated filesystemcheck script - 10-March-2021
# On client servers: /home/teradata/scripts/filesystemcheck/fscheck.sh

#!/bin/bash
directory=/home/teradata/scripts/filesystemcheck/output
find_save(){
        if [ $(df / --output=pcent | awk -F '%' 'NR==2{print $1}') -ge 75 ] ;
        then
        echo "/ FS util => 75%";
        echo "Running checker now";
        find / -xdev -type f -exec du -sh {} ';' | sort -rh | head -50 > $directory/STG-$HOSTNAME-util-`date '+%Y-%m-%d_%H:%M:%S'`.log;
        #chown teradata.admin $directory/*;
        fi;
}

scp_mail(){
scp  $directory/* thakral@dpastgmo:/home/thakral/scripts/filesystemcheck/
ssh -t thakral@dpastgmo 'echo "STG-dpastgespkwik01 / filesystem util breaching 80%" | mailx -v -r fs_utilbot@globe.com.ph -s "STG-dpastgespkwik01 / filesystem util breaching 80%" -a /home/thakral/scripts/filesystemcheck/* "zecvista@globe.com.ph,zemsantos@globe.com.ph,zrtangpus@globe.com.ph,zgqtorres@globe.com.ph,zhcvenal@globe.com.ph"'
}

rm_files(){
rm $directory/*
ssh thakral@dpastgmo 'rm /home/thakral/scripts/filesystemcheck/*'
}

if pgrep -x "find" > /dev/null
then
        echo "Already running, waiting next 5 minutes"
else
        echo "Stopped, running now. Please wait to finish.."
        find_save
        scp_mail
        rm_files
fi
#----------------------------------------------------------------------------------------------------------------------------------------------

# Full script update as of 15-March-2021
#!/bin/bash
directory=/home/teradata/scripts/filesystemcheck/output
find_save(){
        if [ $(df / --output=pcent | awk -F '%' 'NR==2{print $1}') -ge 75 ] ;
        then
        echo "/ FS util => 75%";
        echo "Running checker now";
        find / -xdev -type f -exec du -sh {} ';' | sort -rh | head -50 > $directory/STG-$HOSTNAME-util-`date '+%Y-%m-%d_%H:%M:%S'`.log;
        #chown teradata.admin $directory/*;
        fi;
}

scp_mail(){
scp  $directory/* thakral@dpastgmo:/home/thakral/scripts/filesystemcheck/
ssh -t thakral@dpastgmo 'echo "STG-dpastgespkwik01 / filesystem util breaching 80%" | mailx -v -r fs_utilbot@globe.com.ph -s "STG-dpastgespkwik01 / filesystem util breaching 80%" -a /home/thakral/scripts/filesystemcheck/* "zecvista@globe.com.ph,zemsantos@globe.com.ph,zrtangpus@globe.com.ph,zgqtorres@globe.com.ph,zhcvenal@globe.com.ph"'
}

rm_files(){
rm $directory/*
ssh thakral@dpastgmo 'rm /home/thakral/scripts/filesystemcheck/*'
}

if pgrep -x "find" > /dev/null
then
        echo "Already running, waiting next 5 minutes"
else
        echo "Stopped, running now. Please wait to finish.."
        find_save
        scp_mail
        rm_files
fi
#----------------------------------------------------------------------------------------------------------------------------------------------

#--------------------------------------- ANSIBLE ---------------------------------------
# Requirements
ansible, python3, sshpass

# Cheat sheet
ansible -i hosts all -m ping
ansible -i hosts all -m ping --limit host2 # ping only host2
ansible -i hosts all -m copy -a "src=/root/test_ansible/testfile dest=/tmp/testfile" # Copy the file "testfile" on all hosts in the inventory file 
ansible -i hosts all -m yum -a 'name=ncdu state=present' # Install ncdu package on all hosts 
ansible -i hosts all -m yum -a 'name=ncdu state=absent' # Remove ncdu package on all hosts 
ansible-galaxy init role1 # Build the directory structure for role named role1
ansible-playbook -i hosts p4.yml --check # Dry-run p4.yml playbook 
ansible-playbook -i hosts p4.yml -k # Run p4.yml playbook with password authentication for all hosts 

[ansible-group]
192.168.50.12 ansible_ssh_user=root ansible_ssh_pass=client001

# Check syntax
ansible-playbook /etc/ansible/scripts/httpd.yml --syntax-check

# Push the commands in the playbook to the ansible-group hosts
ansible-playbook httpd.yml

# Inventory / node definitions
/etc/ansible/hosts

#--------------------- ANSIBLE PLAYBOOK MODULES/TEMPLATES/SAMPLES ------------------------

# Creating a sample playbook to install httpd and run it
vi /etc/ansible/scripts/sample.yml # ansible sample playbook in the ansible master server

---
- name: install and run httpd, insert a simple html file
  hosts: ansible-group
  vars:
  		ansible_python_interpreter: /usr/bin/python3
  remote_user: root
  become: true
  tasks:
   - name: install httpd
   	 apt:
   	 	 name: apache2
   	 	 state: latest
   - name: run apache2
     service:
     		 name: apache2
     		 state: started
   - name: create content
     copy:
     	  content: "Ansible installed"
     	  dest: /var/www/html/index.html

# Sample template 1
---
- name: Play 1
  hosts: localhost
  tasks:
	   - name: Execute command 'date'
	     command: date

	   - name: Exec script on server
	     script: test_script.sh

- name: Play 2
hosts: localhost
tasks:
	   - name: Install web service
	      yum:
	      	name: httpd
	      	state: present

	   - name: Start web server
	     service:
	        name: httpd
	       	state: started

# Sample template 2
---
- name: run tasks on all hosts
  hosts: "*"
  tasks:
  	- name: use args, environment and loop with shell
  	  shell: echo "Hello world" > $TARGET
  	  args:
  	  	chdir: /tmp
  	  environment:
  	  	TARGET: "{{ item }}"
  	  loop:
  	  	- test_file1
  	  	- test_file2

# Delete a file
---
- name: delete file
  hosts: ansible-group
  vars:
  		ansible_python_interpreter: /usr/bin/python3
  tasks:
  		- name: delete /tmp/test_file1
  		  file:
  		  		path:/tmp/test_file1
  		  		state: absent


# Create file with permision
--
- tasks:  
  - name: Ansible file module to create new file with permissions.    
    file:      
    path: /path/to/cretae/file/devops.txt    
    state: touch      
    mode: 0421      
    owner: devops

# Create multiple new files
---
- tasks:  
- name: Ansible file module to create multiple files    
  file:       
   path: "{{ item }}"      
   state: touch     
   mode: 0421    
  with_items:    
  - devops1.txt    
  - devops2.txt    
  - devops3.txt  

# Delete multiple files
---
- name: Ansible file module to delete multiple files 
  file:                  
   path: "{{ item }}"    
   state: absent  
  with_items:    
  - devops1.txt    
  - devops2.txt    
  - devops3.txt

# Delete and recreate a filel
---
- name: Delete and Re-Create crunchify.txt file from current directory.
  hosts: local
  connection: local
  gather_facts: True
 
  tasks:
    - name: delete file
      ignore_errors: yes
      file:
        state: absent
        path: crunchify.txt
 
    - name: Ansible create file if it doesn't exist example
      ignore_errors: yes
      file:
        path: "crunchify.txt"
        state: touch

# Install lldpad package
---
- hosts: group1
  tasks:
  - name: Install lldpad package
    yum:
      name: lldpad
      state: latest
  - name: check lldpad service status
    service:
      name: lldpad
      state: started

# Enable SELinux and install Apache
---
- hosts: group1
  tasks:
  - name: Enable SELinux
    selinux:
      state: enabled
    when: ansible_os_family == 'Debian'
    register: enable_selinux

  - debug:
      Imsg: "Selinux Enabled. Please restart the server to apply changes."
    when: enable_selinux.changed == true

- hosts: group2
  tasks:
  - name: Install apache
    yum:
      name: httpd
      state: present
    when: ansible_system_vendor == 'HP' and ansible_os_family == 'RedHat'

# Modify a line in a file
---
- hosts: group2
  tasks:
  - name: sshd config file modify port
    lineinfile:
     path: /etc/ssh/sshd_config
     regexp: 'Port 28675'
     line: '#Port 22'
    notify:
       - restart sshd
handlers
    - name: restart sshd
      service: sshd
        name: sshd
        state: restarted

# Modify DNS resolver 
---
- name: Set resolver for server
  template:
    src: dns.j2
    dest: /etc/resolv.conf
    group: root
    owner: root
    mode: "0644"
    tag: resolver
#----------------------------------------------------------------------------------------------------------------------------------------------

# HOUSEKEEPING FILES

# Filter files according to name and created within a specific date and then zip them
zip -rTm filename.zip $(find dpa_daily_wireline_customers* -type f -newermt Nov-30-2020 ! -newermt Dec-04-2020 )

# Move Files except 1 directory
find path/to/dir/*  \! -name 'this_dir_stays_put' -type d -maxdepth 0 \ -exec mv {​​​​​​}​​​​​​ new/location \;
find . -type f -maxdepth 1 -exec mv {​​​​​​​​}​​​​​​​​ /appl/di_shareddata/di_files/source/subscriber_info/monthly/ \;
find . ! -type d -name '*.xml' ! -type d -name <foldername> -exec mv {} ./Archive \;

# Find files according to name and then list them or delete
find -type f -name "Project_Soundwave_Blaster_Planned_Wireless_20201130_20201227*" -ls
find -type f -name "Project_Soundwave_Blaster_Planned_Wireless_20201130_20201227*" - delete

# Find files and list results to a file
find / -xdev -type f -exec du -sh {} ';' | sort -rh | head -50 > /home/teradata/rootFSutil_20210129.txt 
-xdev = don't descend to other FS or disks

# Zip files and automatically remove the files added to the zip
zip -9 -rTm maillog_01312021.zip maillog-*
-9 = maximum compression
-m = move files after archive
-r = remove files after archive
-T = to test the files first before removing after archive

# Filter by filename and get total file size
find DAILY_PROMO_2019* -type f -exec du -ch {} + | grep total
 
# Filter by filename between date range
In example, includes files from Dec. 1 to 31, 2019 ONLY.
Jan. 1, 2020 files are EXCLUDED.
find ssl_request* -type f -newermt 2019-12-01 ! -newermt 2020-01-01 -exec du -ch {} +
 
# Filter by filename between date range & MOVE files to target directory
find file_name -type f -newermt 2019-10-31 ! -newermt 2020-01-01 -exec mv -i -v {} /appl/di_shareddata/di_files/source/txn_promo ';'
 
# Filter by filename within date range and ZIP them (METHOD 1)
find ssl_request* -type f -newermt 2019-10-01 ! -newermt 2020-01-01 | zip -Tm desmid_ssl_request_2019_logs_20200221 -@
 
# If you want to zip ALL files within date range 
find . -type f -newermt 2019-12-01 ! -newermt 2020-01-01 | zip -Tm esp00_new_frontier_deprover_logs_YYYYMMDD -@

# Filter by filename within date range and ZIP them (METHOD 2)
ls -lrth *201911* | awk '{print $9}' | xargs -I '{}' zip -Tm DAILYPROMO201911.zip '{}'

# Compare difference of two files
diff -q 1st_file_name_path 2nd_file_name_path

# Find files in the given time range inside the current directory, list them and print the filesizes only in bytes (7th column)
find . -type f -newermt June-01-2020 ! -newermt October-01-2020 -ls |  awk -F " " '{print$7}'

# Find files in the given time range inside the current directory, list them and print the filesizes only in bytes (7th column), sum them and print in bytes
find . -type f -newermt June-01-2020 ! -newermt October-01-2020 -ls |  awk -F " " '{print$7}' | awk '{ SUM += $1} END { print SUM }'

# Find files in the given time range inside the current directory, list them and print the filesizes only in bytes (7th column), sum them and print in Gigabytes
find . -type f -newermt June-01-2020 ! -newermt October-01-2020 -ls |  awk -F " " '{print$7}' | awk '{ SUM += $1} END { print SUM }' | awk '{print $1/1024/1024/1024 " GB "}'
#----------------------------------------------------------------------------------------------------------------------------------------------

# Create Remote User 'root' for 114.198.135.18 in mysql

mysql -u root -p

mysql> CREATE USER 'root'@'114.198.135.18' IDENTIFIED BY 'salt and vinegar';

mysql> GRANT ALL ON *.* to 'root'@'114.198.135.18';

mysql> FLUSH PRIVILEGES;
#----------------------------------------------------------------------------------------------------------------------------------------------

# Procedure to Create CSR with SAN

    Login into a server where you have OpenSSL installed
    Go to /tmp or create any directory
    Create a file named san.cnf using vi (if on Unix) with the following information


[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
[ req_distinguished_name ]
countryName                 = Country Name (2 letter code)
stateOrProvinceName         = State or Province Name (full name)
localityName               = Locality Name (eg, city)
organizationName           = Organization Name (eg, company)
commonName                 = Common Name (e.g. server FQDN or YOUR name)
[ req_ext ]
subjectAltName = @alt_names
[alt_names]
DNS.1   = dns1.eglobalreach.net
DNS.2   = dns2.eglobalreach.net


Note: alt_names section is the one you have to change for additional DNS.

    Save the file and execute the following OpenSSL command, which will generate CSR and KEY file

[ openssl req -out sslcert.csr -newkey rsa:2048 -nodes -keyout private.key -config san.cnf ]


This will create sslcert.csr and private.key in the present working directory. You have to send sslcert.csr to certificate signer authority so they can provide you a certificate with SAN.

Verify CSR for SAN
[ openssl req -noout -text -in sslcert.csr | grep DNS ]
#----------------------------------------------------------------------------------------------------------------------------------------------

# Automatic Redirection from HTTP to HTTPS in HTTPD

vim /etc/httpd/conf/httpd.conf

<VirtualHost *:80>
ServerName api1.htechcorp.net
Redirect permanent / https://api1.htechcorp.net/
</VirtualHost> 
#----------------------------------------------------------------------------------------------------------------------------------------------

# Basic Web and SQL Installation 

setenforce 0
yum upgrade -y && yum update -y
yum install net-tools -y
iptables -F; iptables -A INPUT -i lo -j ACCEPT; iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT; iptables -A INPUT -p tcp -s 202.124.138.210/32 -j ACCEPT; iptables -A INPUT -p tcp -s 114.198.135.18/32 --dport 22422 -j ACCEPT; iptables -A INPUT -p tcp --dport 22422 -j DROP; iptables -A INPUT -p tcp -j DROP; iptables -A OUTPUT -o lo -j ACCEPT; iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -nL
yum install httpd -y

#IF HTTPD CAN'T BE INSTALLED
	#Try setenforce 0 & iptables -F

yum install wget -y
yum localinstall https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm -y
yum install mysql-community-server -y 
yum update -y
yum install mysql-server -y
systemctl start mysqld
mysql_secure_installation

# Answer y
# Password: salt and vinegar
# Answer ynyy

rpm -Uvh https://dl.fedoraproject.org/pub/epel/epelyum-release-latest-7.noarch.rpm
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm

yum install epel-release
yum install http://rpms.remirepo.net/enterprise/remi-release-7.rpm
yum install yum-utils
yum-config-manager --enable remi-php72
yum update
yum install php72
yum install php php-mcrypt php-cli php-gd php-curl php-mysql php-ldap php-zip php-fileinfo php-mbstring -y
php -v
systemctl restart httpd 

mysql -p
CREATE USER 'devteam'@'%' IDENTIFIED BY 'garlic and vinegar';
GRANT ALL ON *.* TO 'devteam'@'%';
FLUSH PRIVILEGES;
\q

echo "<?php phpinfo(); ?>" > /var/www/html/index.php
mv /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/welcome.conf_bak
systemctl restart httpd
yum install git -y
yum install composer -y
yum install vim -y
yum update -y
useradd meepwn
useradd -d /var/www/html devteam
usermod -a -G devteam apache
chmod -R g+w /var/www/html
chmod g+s /var/www/html
passwd meepwn
passwd devteam
	#Password: carbonated drink

# SSH
vim /etc/ssh/sshd_config

# Edit the following
# Uncomment Port 22 and change port to 22422
Port 22422

#uncomment PermitRootLogin and change no to yes if you want ssh root@<ip>
PermitRootLogin yes

#Add this line
AllowUsers meepwn devteam

#EDIT /etc/httpd/conf/httpd.conf
vim vim /etc/httpd/conf/httpd.conf
#EDIT DocumentRoot add /public directory
DocumentRoot "/var/www/html/public"
systemctl restart httpd

chmod -R 0775 /var/www/html/ 
chown -R devteam:apache /var/www/html/
systemctl restart httpd

#----------------------------------------------------------------------------------------------------------------------------------------------

# Basic Web Installation 

setenforce 0
yum upgrade -y && yum update -y
yum install net-tools -y

iptables -F; iptables -A INPUT -i lo -j ACCEPT; iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT;
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT; iptables -A INPUT -p tcp -s 202.124.138.210/32 -j ACCEPT;
iptables -A INPUT -p tcp -s 114.198.135.18/32 --dport 22422 -j ACCEPT; iptables -A INPUT -p tcp --dport 22422 -j DROP;
iptables -A INPUT -p tcp -j DROP; iptables -A OUTPUT -o lo -j ACCEPT; iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT;
iptables -nL

yum install httpd -y

# If HTTPD can't be installed, try setenforce 0 and iptables -F

rpm -Uvh https://dl.fedoraproject.org/pub/epel/epelyum-release-latest-7.noarch.rpm
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm

yum install epel-release
yum install http://rpms.remirepo.net/enterprise/remi-release-7.rpm
yum install yum-utils
yum-config-manager --enable remi-php72
yum update
yum install php72
yum install php php-mcrypt php-cli php-gd php-curl php-mysql php-ldap php-zip php-fileinfo php-mbstring -y
php -v
systemctl restart httpd 

echo "<?php phpinfo(); ?>" > /var/www/html/index.php
mv /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/welcome.conf_bak
systemctl restart httpd
yum install git -y
yum install composer -y
yum install vim -y
yum update -y
useradd meepwn
useradd -d /var/www/html devteam
usermod -a -G devteam apache
chmod -R g+w /var/www/html
chmod g+s /var/www/html
passwd meepwn
passwd devteam
# Password: carbonated drink

#----------------------------------------------------------------------------------------------------------------------------------------------

# Secure Shell (SSH)

vim /etc/ssh/sshd_config

# Edit THE following
#uncomment Port 22 and change port to 22422
Port 22422

# uncomment PermitRootLogin and change no to yes if you want to allow root@<IP> -p
PermitRootLogin yes

# Add this line
AllowUsers meepwn devteam

# Edit /etc/httpd/conf/httpd.conf
vim vim /etc/httpd/conf/httpd.conf

# Edit DocumentRoot add /public directory
DocumentRoot "/var/www/html/public"
systemctl restart httpd

chmod -R 0775 /var/www/html/ 
chown -R devteam:apache /var/www/html/
systemctl restart httpd

#----------------------------------------------------------------------------------------------------------------------------------------------

# Secure Copy Protocol (SCP)

# Grabbing a file from my PC to a remote server through port 22422 since it's the SSH port
scp -P22422 meepwn@114.198.135.2:/tmp/file.txt /home/ej/Desktop

# Copying a file from my PC to another server
scp -P22422 /home/ej/Desktop/sendthisfile.txt meepwn@114.198.135.2:/tmp

#----------------------------------------------------------------------------------------------------------------------------------------------

# The only cheat sheet you need to know (alternative to man)

# Make sure to have the curl tool installed
which curl 

# Running the above command should output /usr/bin/curl
# It is not installed if it does not ouput /usr/bin/curl, hence, install it first

# Run the command below to see some options for cheat.sh
curl cheat.sh

# Type any tool/command next to cheat.sh to see a summary of how to use that specific tool, example you want to learn the tar command
curl cheat.sh/tar

#----------------------------------------------------------------------------------------------------------------------------------------------

COMBINING TWO CSV FILES IN PYTHON USING PANDAS

Sample (when having more columns):
df1 = pd.read_csv('file1.csv')
df2 = pd.read_csv('file2.csv')
df1.merge(df2, how='left', on='City')

#----------------------------------------------------------------------------------------------------------------------------------------------

SAVING 2 DATA FILES IN SEPARATE SHEETS IN PYTHON USING PANDAS

from xlsxwriter import Workbook

writer2 = pd.ExcelWriter('mult_sheets_2.xlsx', engine = 'xlsxwriter')
df_1.to_excel(writer2, sheet_name = 'df_1', index = False)
df_2.to_excel(writer2, sheet_name = 'df_2', index = False)
writer2.save()

#----------------------------------------------------------------------------------------------------------------------------------------------

# PYTHON WITH PANDAS SCRIPT TO MERGE TWO .CSV FILES (GLOBE PROJECT)
# Changelog 
# Version 1.00 28-Jan-2021
#
# Version 1.0.2 25-Feb-2020
# print_prod_CPU.to_csv to print_stg_CPU.head(29).to_csv to only print the 30 PROD servers for CPU util
# print_prod_Mem.to_csv to print_stg_Mem.head(29).to_csv to only print the 30 PROD servers for Mem util
# print_stg_CPU.to_csv to print_stg_CPU.head(30).to_csv to only print the 30 STG servers for CPU util
# print_stg_Mem.to_csv to print_stg_Mem.head(30).to_csv to only print the 30 STG servers for Mem util
# Organized the directories
# Output file now consolidated in the /weekly_output directory
# Added cleanup commands such as removing additional column and resetting the index number in the final output
# Combined outputs for prod and staging environments
# Combined all .csv outputs to multiple sheets in one .xlsx file
# Renamed python script to run-me.ipynb
#--------------------------------------------------------------------------------
# Files needed
# 1. envMem.csv - from GoogleSpreadSheet
# 2. envCPU.csv - from GoogleSpreadSheet
# 3. prodMem.csv - from Splunk (weekly)
# 4. prodCPU.csv - from Splunk (weekly)
# 5. stgCPU.csv  - from Splunk (weekly)
# 6. stgMem.csv - from Splunk (weekly)
# 7. prodFS.csv - from Splunk (weekly)
# --------------------------------------------------------------------------------
# Links:
# DPA Environment - https://docs.google.com/spreadsheets/d/1Ll7-mdb8tsGUKIDYJ-dMEBmydxXf24krk8J7r1RIUog/edit#gid=588246582
# Splunk (DPA PROD/Staging 2) - http://10.69.81.41:8000/en-US/app/splunk_app_for_linux_Infrastructure/dashboards
# --------------------------------------------------------------------------------
# Helpful commands
#
# print(mem_df.loc[[20]]) # printing x row
# envMem_df.tail(10)
# mem_df.tail(10)
# mem_df = df.sort_values(by=['Column_name'], ascending=True) # to sort by column
# DPAenv_df.columns # for reference to check which column to join from DPAenv
# mergedData.to_csv('filename') # for exporting
# mergedData.to_csv('filename', index=False) # to remove the index column
# --------------------------------------------------------------------------------
# LEGEND:
# FS - File System
# df - data file (.csv, xlx, etc)
# env - environment (official .csv Environment file from google sheets)
# --------------------------------------------------------------------------------
# How To Use
# 1. Rename/save the .csv files to prodMem.csv, stgMem.csv, prodCPU.csv, stgCPU.csv, prodFS.csv
# 2. Get Environment files from Google Sheet and name them as envMem.csv, envCPU.csv & envFS.csv
# 3. Place them in Jupyter Notebook dir (./DPA_report/sources/)

import pandas as pd
pd.set_option('display.max_columns', 500)
pd.set_option('display.width', 100)
from xlsxwriter import Workbook

# Environmnet files from Google Spreadsheet
envMem_df = pd.read_csv('./sources/envMem.csv')
envCPU_df = pd.read_csv('./sources/envCPU.csv')
envFS_df = pd.read_csv('./sources/envFS.csv')

# Weekly data from Splunk
prodMem_df = pd.read_csv('./sources/prodMem.csv')
stgMem_df = pd.read_csv('./sources/stgMem.csv')
prodCPU_df = pd.read_csv('./sources/prodCPU.csv')
stgCPU_df = pd.read_csv('./sources/stgCPU.csv')
prodFS_df = pd.read_csv('./sources/prodFS.csv')

# To replace the NaN
envMem_df = envMem_df[envMem_df['Host'].isna() == False]
envCPU_df = envCPU_df[envCPU_df['Host'].isna() == False]
envFS_df = envFS_df[envFS_df['Mount'].isna() == False]

prodMem_df = prodMem_df[prodMem_df['Host'].isna() == False]
stgMem_df = stgMem_df[stgMem_df['Host'].isna() == False]
prodCPU_df = prodCPU_df[prodCPU_df['Host'].isna() == False]
stgCPU_df = stgCPU_df[stgCPU_df['Host'].isna() == False]
prodFS_df = prodFS_df[prodFS_df['Used'].isna() == False]

# Merging .csv files for Memory usage
prod_Mem_mergeData = pd.merge(envMem_df, prodMem_df, left_on='Host', right_on='Host', how='right').sort_values('IP Address_x')
stg_Mem_mergeData = pd.merge(envMem_df, stgMem_df, left_on='Host', right_on='Host', how='right').sort_values('IP Address_x')

# Merging .csv files for CPU usage
prod_CPU_mergeData = pd.merge(envCPU_df, prodCPU_df, left_on='Host', right_on='Host', how='right').sort_values('IP Address_x')
stg_CPU_mergeData = pd.merge(envCPU_df, stgCPU_df, left_on='Host', right_on='Host', how='right').sort_values('IP Address_x')

# Merging the two .csv files according to 'Host' and 'Mount' via inner join for FS usage (PROD only)
prod_FS_mergeData = pd.merge(envFS_df,prodFS_df, left_on=['Host', 'Mount'],right_on=['Host','Mount'], how='inner')
#prod_FS_mergeData[['Host', 'Mount', 'Used']].sort_values(['Host', 'Mount']) # uncomment to print to screen / comment to unprint
mergeDataPrint = prod_FS_mergeData[['Host', 'Mount', 'Used']].sort_values(['Host', 'Mount']) 
mergeDataPrint.head(264).to_csv('./raw/prod_FS_Weekly_Output.csv', index = False) 
#print(mergeDataPrint.head(264))

# Assigning variables for printing
print_prod_Mem = prod_Mem_mergeData[['Host', 'IP Address_x', 'Used']]
print_stg_Mem = stg_Mem_mergeData[['Host', 'IP Address_x', 'Used']]
print_prod_CPU = prod_CPU_mergeData[['Host', 'IP Address_x', 'Used']]
print_stg_CPU = stg_CPU_mergeData[['Host', 'IP Address_x', 'Used']]

# Uncomment to PRINT TO SCREEN / comment to hide
#print_prod_Mem.head(29)
#print_stg_Mem.head(30)
#print_prod_CPU
#print_stg_CPU.head(30)
#prodFS_df.head(10)

# Exporting to .csv for individual utils
print_prod_Mem.head(29).to_csv('./raw/prod_Mem_Weekly_Output.csv') # working
print_stg_Mem.head(30).to_csv('./raw/stg_Mem_Weekly_Output.csv') # working
print_prod_CPU.head(29).to_csv('./raw/prod_CPU_Weekly_Output.csv') # working
print_stg_CPU.head(30).to_csv('./raw/stg_CPU_Weekly_Output.csv') # working

# PROD & STG MEM - Appending the two .csv output for Mem
mem_prod = pd.read_csv('./raw/prod_Mem_Weekly_Output.csv')
mem_stg  = pd.read_csv('./raw/stg_Mem_Weekly_Output.csv')
mem_weekly = mem_prod.append(mem_stg)# <-- append step
mem_weekly = mem_weekly.drop(mem_weekly.columns[[0]], axis=1) # <-- removes additional column created
mem_weekly.reset_index(drop=True, inplace=True) # <-- resets the index number
mem_weekly.to_csv('./raw/mem_weekly.csv', index = False) # <-- index=False to remove index upon saving
#print(mem_weekly)

# PROD & STG CPU - Appending the two .csv output
prod_CPU = pd.read_csv('./raw/prod_CPU_Weekly_Output.csv')
stg_CPU  = pd.read_csv('./raw/stg_CPU_Weekly_Output.csv')
CPU_weekly = prod_CPU.append(stg_CPU) # <-- append step
CPU_weekly = CPU_weekly.drop(CPU_weekly.columns[[0]], axis=1) # <-- removes additional column created
CPU_weekly.reset_index(drop=True, inplace=True) # <-- resets the index number
CPU_weekly.to_csv('./raw/CPU_weekly.csv', index = False) # <-- index=False to remove index upon saving
#print(CPU_weekly)

# Prod FS
prod_weekly = pd.read_csv('./raw/prod_FS_Weekly_Output.csv')

# Display the number of rows and columns (rows,columns). Uncomment to view
#mem_weekly.shape
#CPU_weekly.shape
#prod_weekly.shape

# Write to one excel file with multiple sheets
writer = pd.ExcelWriter('output.xlsx', engine='xlsxwriter')
CPU_weekly.to_excel(writer, sheet_name = 'CPU', index = False)
mem_weekly.to_excel(writer, sheet_name = 'mem', index = False)
prod_weekly.to_excel(writer, sheet_name = 'FS', index = False)
writer.save()
#----------------------------------------------------------------------------------------------------------------------------------------------

# GET OS USER SCRIPT
#!/bin/bash
# Needed:
# Username,User ID,Name,Last Login,Last Password Change, PROFILE, Account Create Date, Account Expiry, Account Status

awk -F ":" '{print $1 "|" $3 "|" $5} /etc/passwd > ./output/data.txt
column -t -s"|" ./output/data.txt > ./output/data-tabled.txt
lastlog > /home/teradata/scripts/getosuser/output/lastlog.csv
zip -rTm ./output/dpacamel03-osuser.zip ./output/*
cp ./output/dpacamel03-osuser.zip /home/ec2-user/
chown ec2-user.ec2-user /home/ec2-user/dpacamel03-osuser.zip


# Print output here
for user in $(cut -d: -f1 /etc/passwd | sort -t':' -k1,1);
do echo "Username: $user";
#sudo chage -l $user 2>&1;
done
#----------------------------------------------------------------------------------------------------------------------------------------------

# Save directory to a variable
#!/bin/bash
# sample script to change directory and save a file
WORKDIR=/home/file/n34_panda
cd $WORKDIR
#----------------------------------------------------------------------------------------------------------------------------------------------

# Disable password aging
# To disable password aging / expiration for user foo, type command as follows and set:
Minimum Password Age to 0
Maximum Password Age to 99999
Password Inactive to -1
Account Expiration Date to -1
Interactive mode command:

chage -I -1 -m 0 -M 99999 -E -1 dsatr_dsa_dpa_sftp
#----------------------------------------------------------------------------------------------------------------------------------------------

# RHEL RESET ROOT PASSWORD

1. Boot to single-user mode (run level 1/skip intrd and intramfs)
   Reboot system and press e to edit the GRUB.
2. Look for intrd and intramfs, before that line add "rd.break"
3. Make changes to /sysroot but remount it as read-writable first.
   # mount -o, remount /sysroot
4. Chroot to /sysroot (jail the user to /sysroot)
   # chroot /sysroot
5. Change the root password
   # passwd
   # <enter new root passwd>
6. RHEL/CentOS uses SELinux by default, hence create a new hidden which will automatically perform a relabel of all files on next boot
   # touch /.autorelabel
7. reboot -f
#----------------------------------------------------------------------------------------------------------------------------------------------

# Create one partition having 100MB  and mount to /data
1. Use fdisk /dev/hda to create new partition.
2. Type n For New partitions.
3. It will ask for Logical or Primary Partitions. Press l for logical.
4. It will ask for the Starting Cylinder: Use the Default by pressing Enter
Key.
5. Type the Size: +100M you can specify either Last cylinder of size here.
6. Press P to verify the partitions lists and remember the partitions name.
7. Press w to write on partitions table.
8. Either Reboot or use partprobe command.
9. Use mkfs -t ext3 /dev/hda?

OR -
mke2fs -j /dev/hda? To create ext3 filesystem.
vi /etc/fstab
Write:
/dev/hda? /data ext3 defaults 1 2
Verify by mounting on current Sessions also: mount /dev/hda? /data
#----------------------------------------------------------------------------------------------------------------------------------------------

# Check if file exists
FILE=/etc/resolv.conf
if test -f "$FILE"; then
    echo "$FILE exists."
fi
#----------------------------------------------------------------------------------------------------------------------------------------------

# Adding a line on the first line of the file
awk -i inplace 'BEGINFILE{print "first line"}{print}' foo.sh
sed -i '1i #!/bin/bash' foo.sh
