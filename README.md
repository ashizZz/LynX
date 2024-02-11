# LynX

## Overview
LynX: Linux System Examination, the ultimate incident response emergency tool. It detects vulnerabilities across 13 categories, including configuration, network, and services, while also identifying malware, rootkits, SSH threats, mining attacks, and more.

## Functionalities 

- Basic configuration check
- System configuration change check
- System information:
  - IP address
  - User
  - Boot time
  - System version
  - Hostname
  - Server SN
- CPU usage
- Login user information
- Top CPU processes (TOP 15)
- Top memory processes (TOP 15)
- Disk space remaining check
- Disk mounting
- Common software check
- /etc/hosts file check
- Network and traffic check:
  - ifconfig
  - Network traffic
  - Port listening
  - Open ports
  - Network connections
  - TCP connection status
  - Routing table
  - Routing forwarding
  - DNS Server
  - ARP
  - Network card promiscuous mode check
  - iptables firewall
- Task schedule check:
  - Current user task schedule
  - /etc/system task schedule
  - Task schedule file creation time
  - Crontab backdoor check
- Environment variable check:
  - env
  - path
  - LD_PRELOAD
  - LD_ELF_PRELOAD
  - LD_AOUT_PRELOAD
  - PROMPT_COMMAND
  - LD_LIBRARY_PATH
  - ld.so.preload
- User information check:
  - Login users
  - passwd file modification date
  - sudoers
  - Login information (w/last/lastlog)
  - Historical login IP
- Services check:
  - SystemD running services
  - SystemD service creation time
- Bash check:
  - History
  - History command audit
  - /etc/profile
  - $HOME/.profile
  - /etc/rc.local
  - ~/.bash_profile
  - ~/.bashrc
  - Bash bounce shell
- File check:
  - Hidden files
  - System file modification time detection
  - Temporary file check (/tmp /var/tmp /dev/shm)
  - alias
  - SUID special permission check
  - Processes exist file not found
  - Files modified in the last seven days (mtime)
  - Files modified in the last seven days (ctime)
  - Large files >200mb
  - Sensitive file audit (nmap/sqlmap/ew/frp/nps and other commonly used hacker tools)
  - Suspicious hacker files (hacker uploaded wget/curl and other programs, or malicious programs changed to normal software such as nps files changed to mysql)
- Kernel Rootkit check:
  - Suspicious modules in lsmod
  - Kernel symbol table check
  - Rootkit hunter check
  - Rootkit .ko module check
- SSH check:
  - SSH brute force
  - SSHD detection
  - SSH backdoor configuration
  - SSH inetd backdoor check
  - SSH key
- Webshell check:
  - PHP webshell check
  - JSP webshell check
- Mining file/process check:
  - Mining file check
  - Mining process check
  - WorkMiner detection
  - Ntpclient detection
- Supply chain poisoning check:
  - Python PIP poisoning check
- Server risk check:
  - Redis weak password detection


## Usages and Installation

    git clone https://github.com/al0ne/LinuxCheck.git  
    chmod u+x LinuxCheck.sh
    ./LinuxCheck.sh

## References
https://github.com/grayddq/GScan 

https://github.com/CISOfy/lynis
