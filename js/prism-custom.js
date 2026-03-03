/**
 * Prism.js Custom Extensions
 * ==========================
 *
 * Custom syntax highlighting extensions for domain-specific tools and commands.
 * This file can be customized or replaced for different documentation domains.
 *
 * Current configuration: Cybersecurity/Penetration Testing tools
 *
 * How it works:
 *   1. Prism parses bash/powershell syntax first (comments, strings, variables, operators)
 *   2. This script then highlights tool/command names in remaining bare text only
 *   3. Safe word boundaries prevent false matches inside paths, URLs, and flags
 *
 * To customize for a different domain:
 *   1. Replace the keyword lists with your domain-specific tools
 *   2. Or delete this file entirely (Prism works without it)
 * 
 * Author: @TristanInSec / HackWiki
 */

(function() {
    'use strict';

    if (typeof Prism === 'undefined') {
        console.warn('Prism not loaded - custom extensions skipped');
        return;
    }

    // =========================================================================
    // SAFE BOUNDARY HELPERS
    // =========================================================================

    /**
     * Build a regex with safe word boundaries that prevent matching inside:
     *   - Paths:   /dirb/common.txt, /usr/share/seclists/
     *   - URLs:    github.com/ffuf/ffuf
     *   - Flags:   --top-ports, -sT
     *   - Dotted:  crt.sh preceded by path separator
     *
     * Uses \b for standard word boundaries plus negative lookbehind/lookahead.
     * Lookbehind rejects paths (\w followed by / or \) and flags/dotted names
     * (preceded by - or .), but allows ./ and .\ current-directory prefixes.
     */
    function safeWordPattern(words) {
        var escaped = words.map(function(w) {
            return w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        });
        var pattern = escaped.join('|');
        return new RegExp('(?<!\\w[/\\\\]|[-.])(\\b(?:' + pattern + ')\\b)(?![/\\\\\\-.])', 'g');
    }

    // =========================================================================
    // TEXT NODE PROCESSING
    // =========================================================================

    /**
     * Apply highlighting only to text NOT already inside Prism token spans.
     *
     * This prevents:
     *   - "use" matching inside comments: # use $1, default to...
     *   - "threads" matching as variable name: threads="${THREADS:-10}"
     *   - Tools matching inside strings: "nmap results saved"
     *   - Double-highlighting of already-parsed syntax
     */
    function highlightBareText(element, replacements) {
        var nodes = [];
        var walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);

        // Collect text nodes that aren't inside existing Prism tokens
        while (walker.nextNode()) {
            var node = walker.currentNode;
            if (!node.textContent.trim()) continue;

            var parent = node.parentElement;
            var insideToken = false;
            while (parent && parent !== element) {
                if (parent.classList && parent.classList.contains('token')) {
                    insideToken = true;
                    break;
                }
                parent = parent.parentElement;
            }

            if (!insideToken) {
                nodes.push(node);
            }
        }

        // Process in reverse to preserve DOM positions
        for (var i = nodes.length - 1; i >= 0; i--) {
            var textNode = nodes[i];

            // Carry lookbehind context from preceding Prism token so that
            // e.g. "-" operator + bare "split" is seen as "-split" (a flag,
            // not the split command).  Only inject the last character.
            var prefix = '';
            var prev = textNode.previousSibling;
            if (prev && prev.nodeType === 1) {
                var pt = prev.textContent;
                if (pt && /[-/\\.]$/.test(pt)) {
                    prefix = pt.slice(-1);
                }
            }

            // Suffix context: restore digit stolen by Prism file-descriptor redirect.
            // e.g. Prism tokenizes "sqlite3>" as text "sqlite" + operator "3>"
            var suffix = '';
            var nextSib = textNode.nextSibling;
            if (nextSib && nextSib.nodeType === 1) {
                var nt = nextSib.textContent;
                if (nt && /^\d[<>]/.test(nt)) {
                    suffix = nt.charAt(0);
                }
            }

            var html = escapeHtml(prefix + textNode.textContent + suffix);
            var changed = false;

            for (var j = 0; j < replacements.length; j++) {
                var regex = replacements[j][0];
                var cssClass = replacements[j][1];
                regex.lastIndex = 0;
                var newHtml = html.replace(regex, '<span class="token ' + cssClass + '">$1</span>');
                if (newHtml !== html) {
                    html = newHtml;
                    changed = true;
                }
            }

            if (changed) {
                if (prefix) html = html.substring(prefix.length);
                // If suffix digit was consumed by a match (now inside a <span>),
                // steal it back from the operator span.  If not consumed, strip it.
                if (suffix) {
                    var eSuffix = escapeHtml(suffix);
                    if (html.endsWith(eSuffix + '</span>')) {
                        // Digit is inside our new tool span — keep it, fix operator
                        nextSib.textContent = nextSib.textContent.substring(suffix.length);
                    } else {
                        // Digit wasn't part of a match — strip it
                        html = html.slice(0, -eSuffix.length);
                    }
                }
                var frag = document.createRange().createContextualFragment(html);
                textNode.parentNode.replaceChild(frag, textNode);
            }
        }
    }

    /**
     * Re-escape text content for safe HTML insertion.
     * DOM textContent is unescaped; we need HTML entities before injecting spans.
     */
    function escapeHtml(text) {
        return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // =========================================================================
    // KEYWORD DEFINITIONS
    // =========================================================================

    // ── Metasploit console commands ─────────────────────────────────────
    // Generic words like "use", "set", "show" are safe here because the
    // text-node approach skips comments, strings, and variable assignments.
    var msfKeywords = safeWordPattern([
        // Core commands
        'use', 'exploit', 'run', 'set', 'unset', 'setg', 'getg',
        'show', 'search', 'info', 'options', 'sessions',
        'background', 'back', 'help', 'load', 'unload',
        // Database
        'db_nmap', 'db_import', 'hosts', 'services', 'vulns',
        'creds', 'loot', 'workspace',
        // Session/job management
        'payloads', 'auxiliary', 'resource', 'plugins',
        'pushm', 'popm', 'spool', 'reload_all',
        // Scripting
        'irb', 'makerc', 'loadpath', 'go_pro', 'arp_scanner',
        // Navigation
        'check', 'connect', 'edit', 'save', 'get',
        'cve', 'jobs',
        // Meterpreter commands
        'sysinfo', 'getuid', 'getpid', 'getsystem',
        'upload', 'download', 'migrate', 'execute', 'shell',
        'hashdump', 'portfwd', 'screenshot',
        'keyscan_start', 'keyscan_stop', 'keyscan_dump',
        'list_tokens', 'impersonate_token',
        'creds_all', 'creds_msv', 'creds_kerberos', 'kiwi_cmd',
        'incognito', 'kiwi'
    ]);

    // ── Security & penetration testing tools ────────────────────────────
    var secTools = safeWordPattern([
        // Scanning & enumeration
        'nmap', 'masscan', 'rustscan', 'zmap',
        'nikto', 'nuclei', 'whatweb', 'wpscan', 'joomscan', 'droopescan',
        // Fuzzing & content discovery
        'dirb', 'gobuster', 'ffuf', 'feroxbuster', 'dirsearch', 'wfuzz',
        // SQL & injection
        'sqlmap', 'commix',
        // Suites & frameworks
        'burpsuite', 'wireshark', 'metasploit', 'msfconsole', 'msfvenom',
        'msf-pattern_create', 'msf-pattern_offset',
        // Cracking
        'hydra', 'john', 'hashcat', 'medusa', 'patator',
        'hashid', 'hash-identifier', 'cewl', 'crunch', 'unshadow',
        // Network tools
        'netcat', 'nc', 'ncat', 'socat',
        'curl', 'wget', 'ssh', 'scp', 'ftp', 'telnet',
        'tcpdump', 'tshark', 'dumpcap', 'editcap', 'mergecap', 'capinfos', 'base64',
        // SMB / Windows / AD
        'enum4linux', 'enum4linux-ng', 'smbclient', 'smbmap',
        'crackmapexec', 'netexec', 'nxc', 'evil-winrm',
        'impacket', 'bloodhound', 'bloodhound-python',
        'mimikatz', 'rubeus', 'certify', 'certipy-ad',
        'powerview', 'sharphound', 'responder',
        'rpcclient', 'ldapsearch', 'nbtscan', 'nltest',
        'kerbrute', 'pypykatz',
        // Impacket scripts
        'impacket-addcomputer', 'impacket-atexec',
        'impacket-changepasswd', 'impacket-dacledit',
        'impacket-dcomexec', 'impacket-findDelegation',
        'impacket-GetADUsers', 'impacket-GetNPUsers',
        'impacket-getST', 'impacket-getTGT',
        'impacket-GetUserSPNs', 'impacket-lookupsid',
        'impacket-mssqlclient', 'impacket-ntlmrelayx',
        'impacket-owneredit', 'impacket-psexec',
        'impacket-rbcd', 'impacket-rpcdump',
        'impacket-samrdump', 'impacket-secretsdump',
        'impacket-services', 'impacket-smbclient',
        'impacket-smbexec', 'impacket-ticketConverter',
        'impacket-ticketer', 'impacket-wmiexec',
        // C2 frameworks
        'sliver-client', 'sliver-server', 'sliver', 'havoc',
        'beacon', 'dnscat2', 'dnscat',
        // Evasion & payload generation
        'donut', 'osslsigncode', 'phpggc',
        // Wireless / MITM / physical
        'bettercap', 'ettercap', 'aircrack-ng', 'airmon-ng', 'airodump-ng',
        'wifite', 'reaver', 'wash',
        'mitmproxy', 'mitmdump', 'mitmweb',
        'proxmark3', 'pm3', 'bluetoothctl', 'hcitool', 'hciconfig',
        'l2ping', 'sdptool', 'nfc-list', 'nfc-poll',
        // VoIP
        'svmap', 'svwar', 'svcrack',
        // Exploit development
        'gdb', 'pwndbg', 'checksec', 'ROPgadget', 'ropper',
        'nasm', 'gcc', 'i686-w64-mingw32-gcc',
        'x86_64-w64-mingw32-gcc', 'x86_64-w64-mingw32-strip',
        'strace', 'ltrace', 'objdump', 'readelf', 'objcopy',
        // Exploit research
        'searchsploit', 'exploitdb',
        // OSINT & recon
        'subfinder', 'amass', 'theHarvester', 'recon-ng', 'maltego',
        'shodan', 'censys', 'dnsenum', 'dnsrecon', 'fierce',
        'whois', 'dig', 'host', 'nslookup', 'traceroute',
        'certstream', 'trufflehog', 'metagoofil',
        // Web recon
        'arjun', 'paramspider', 'gau', 'waybackurls',
        'httprobe', 'aquatone', 'eyewitness', 'gowitness',
        'linkfinder', 'secretfinder', 'gf', 'qsreplace', 'unfurl', 'anew',
        // DNS brute
        'httpx', 'dnsx', 'shuffledns', 'puredns', 'massdns',
        'altdns', 'dnsgen', 'gotator',
        'sublist3r', 'assetfinder', 'findomain',
        'github-subdomains', 'gitlab-subdomains', 'crt.sh', 'certspotter',
        // Mobile security
        'frida', 'frida-ps', 'objection',
        'adb', 'apktool', 'jadx', 'aapt',
        'd2j-dex2jar', 'jarsigner', 'keytool', 'androguard',
        'ideviceinfo', 'ideviceinstaller', 'idevice_id', 'iproxy',
        'plistutil',
        // Forensics & reverse engineering
        'volatility', 'autopsy', 'sleuthkit', 'yara', 'binwalk', 'foremost',
        'vol', 'scalpel', 'photorec', 'bulk_extractor',
        'r2', 'rabin2', 'rahash2',
        'diec', 'de4dot', 'monodis', 'javap',
        'ssdeep', 'upx',
        'fls', 'icat', 'istat', 'mmls', 'fsstat', 'blkls',
        'blkcat', 'blkstat', 'img_stat', 'tsk_recover', 'mactime',
        'dc3dd', 'avml',
        'ewfacquire', 'ewfinfo', 'ewfmount', 'ewfverify',
        'reglookup', 'regripper', 'chntpw',
        'dwarf2json',
        'nfdump', 'nfpcapd',
        'sigma',
        'inetsim',
        // Defensive & hardening
        'clamav', 'rkhunter', 'chkrootkit', 'lynis',
        'aide', 'auditctl', 'augenrules', 'aureport', 'ausearch',
        'suricata', 'suricata-update', 'suricatasc',
        'ufw', 'nft',
        'openvas', 'nessus', 'arachni', 'zap',
        'w3af', 'skipfish', 'wapiti', 'vega', 'acunetix',
        'appscan', 'fortify', 'checkmarx', 'sonarqube',
        'bandit', 'safety', 'pip-audit', 'npm-audit',
        'snyk', 'trivy', 'grype', 'syft', 'cosign', 'sigstore',
        // Pivoting & tunneling
        'chisel', 'ligolo-agent', 'ligolo-proxy',
        'proxychains', 'proxychains4', 'sshuttle',
        // SNMP
        'snmpwalk', 'snmpget', 'snmpset', 'snmp-check', 'onesixtyone',
        // Database clients
        'mysql', 'psql', 'sqlplus', 'mongosh', 'redis-cli', 'sqlite3',
        'odat',
        // SSL/TLS testing
        'sslscan', 'sslyze', 'testssl.sh', 'openssl',
        // Remote access
        'xfreerdp', 'xfreerdp3', 'rdesktop', 'vncviewer', 'vncpwd',
        // Social engineering
        'setoolkit', 'evilginx2', 'swaks', 'smtp-user-enum',
        // Web testing
        'cadaver', 'davtest', 'websocat', 'wafw00f', 'webanalyze',
        'wappalyzer',
        // Misc security tools
        'ysoserial.exe', 'ipmitool', 'ethtool',
        'linpeas.sh', 'winPEASx64.exe', 'DumpIt.exe',
        'tftp', 'insmod', 'rmmod',
        // Coding & interpreters
        'powershell', 'python', 'python3', 'ruby', 'perl', 'php',
        'java', 'go',
        'script', 'stty'
    ]);

    // ── System / shell commands ─────────────────────────────────────────
    var sysCommands = safeWordPattern([
        // Network
        'ifconfig', 'ip', 'iptables', 'iptables-save', 'netstat', 'ss',
        'hostname', 'ping', 'ping6', 'arp', 'arping', 'arp-scan',
        'fping', 'mtr', 'route', 'iw', 'iwconfig',
        'netdiscover', 'rpcinfo',
        // Process management
        'lsof', 'ps', 'top', 'htop', 'kill', 'pkill', 'killall',
        'bg', 'fg', 'jobs', 'disown', 'nohup', 'wait',
        'screen', 'tmux',
        // Service management
        'systemctl', 'service', 'journalctl', 'dmesg', 'sysctl', 'sshd',
        // Identity & access
        'uname', 'whoami', 'id', 'groups', 'passwd', 'sudo', 'su',
        'useradd', 'usermod', 'visudo', 'sudoedit',
        'last', 'lastb', 'lastlog', 'who', 'w',
        'getenforce', 'sestatus',
        // Permissions & capabilities
        'chmod', 'chown', 'chgrp', 'umask',
        'getcap', 'capsh', 'setarch',
        // Search & text processing
        'find', 'locate', 'updatedb', 'grep', 'egrep',
        'awk', 'sed', 'cut', 'sort', 'uniq', 'wc', 'tr',
        'head', 'tail', 'cat', 'less', 'more', 'tee',
        'diff', 'split',
        // File operations
        'ls', 'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'ln', 'touch',
        'tree',
        // Editors
        'vim', 'nano',
        // Archive & compression
        'tar', 'gzip', 'gunzip', 'zip', 'unzip', 'xz', 'zcat',
        // Encoding & hashing
        'xxd', 'hexdump', 'strings', 'file',
        'md5sum', 'sha1sum', 'sha256sum',
        // System info
        'df', 'du', 'free', 'uptime', 'lsblk', 'lscpu', 'lsb_release',
        'mount', 'umount', 'blockdev',
        // Package management
        'apt', 'dpkg', 'pip', 'npm', 'rpm', 'make',
        // Misc utilities
        'echo', 'printf', 'date', 'sleep', 'timeout', 'watch',
        'read', 'export', 'env', 'type', 'which', 'command',
        'crontab', 'logger', 'mkfifo',
        'dd', 'rsync', 'pmap', 'ldd',
        // Container / VM
        'docker', 'nsenter', 'VBoxManage', 'qemu-img',
        // VPN
        'wg',
        // Windows CMD (for mixed bash/cmd code blocks)
        'systeminfo', 'ipconfig', 'net', 'reg', 'wmic',
        'certutil', 'robocopy', 'cmdkey', 'findstr',
        'icacls', 'sc', 'schtasks', 'tasklist',
        // Version control
        'git'
    ]);

    // ── PowerShell cmdlets ──────────────────────────────────────────────
    var psCommands = safeWordPattern([
        // Get cmdlets
        'Get-Acl', 'Get-ADComputer', 'Get-ADDefaultDomainPasswordPolicy',
        'Get-ADDomain', 'Get-ADDomainController', 'Get-ADForest',
        'Get-ADGroup', 'Get-ADGroupMember', 'Get-ADTrust', 'Get-ADUser',
        'Get-ChildItem', 'Get-CimInstance', 'Get-Command', 'Get-ComputerInfo',
        'Get-Content', 'Get-Credential', 'Get-Date',
        'Get-DnsClientServerAddress', 'Get-EventLog', 'Get-ExecutionPolicy',
        'Get-FileHash', 'Get-GPO', 'Get-GPPermission', 'Get-Help',
        'Get-HotFix', 'Get-ItemProperty', 'Get-ItemPropertyValue',
        'Get-LocalGroup', 'Get-LocalGroupMember', 'Get-LocalUser',
        'Get-Member', 'Get-NetFirewallRule', 'Get-NetIPAddress',
        'Get-NetIPConfiguration', 'Get-NetNeighbor', 'Get-NetRoute',
        'Get-NetTCPConnection', 'Get-Process', 'Get-PSDrive',
        'Get-ScheduledTask', 'Get-ScheduledTaskInfo', 'Get-Service',
        'Get-WinEvent', 'Get-WmiObject',
        // Set cmdlets
        'Set-ADAccountControl', 'Set-ADAccountPassword', 'Set-Content',
        'Set-ExecutionPolicy', 'Set-ItemProperty', 'Set-SeBackupPrivilege',
        'Set-WmiInstance',
        // Invoke cmdlets
        'Invoke-CimMethod', 'Invoke-Command', 'Invoke-GPUpdate',
        'Invoke-Mimikatz', 'Invoke-Obfuscation', 'Invoke-RestMethod',
        'Invoke-WebRequest', 'Invoke-AtomicTest',
        // New / Add / Remove cmdlets
        'Add-ADGroupMember', 'Add-Content', 'Add-DomainObjectAcl', 'Add-Type',
        'New-Item', 'New-ItemProperty', 'New-Object', 'New-PSSession',
        'New-ScheduledTaskAction', 'New-ScheduledTaskPrincipal',
        'New-ScheduledTaskTrigger', 'New-Service',
        'Register-ScheduledTask', 'Unregister-ScheduledTask',
        // Session cmdlets
        'Enter-PSSession', 'Exit-PSSession',
        // Pipeline cmdlets
        'Where-Object', 'Select-Object', 'Sort-Object', 'Group-Object',
        'Measure-Object', 'ForEach-Object', 'Format-Table', 'Format-List',
        // I/O cmdlets
        'Write-Host', 'Write-Output', 'Read-Host',
        'Out-File', 'Out-Null', 'Out-String',
        'Import-Csv', 'Export-Csv', 'Import-Module',
        'ConvertFrom-Json', 'ConvertTo-Json',
        // File & misc cmdlets
        'Copy-Item', 'Resolve-DnsName', 'Select-String',
        'Start-BitsTransfer', 'Start-Process', 'Start-Service',
        'Start-ScheduledTask',
        'Test-Connection', 'Test-NetConnection', 'Test-Path', 'Test-WSMan',
        'Update-Help', 'Install-AtomicRedTeam'
    ]);

    // =========================================================================
    // CUSTOM LANGUAGE: Windows CMD / Batch (```cmd or ```batch)
    // =========================================================================

    // Define only if Prism's batch plugin is not already loaded
    if (!Prism.languages.batch) {
        Prism.languages.batch = {
            'comment': [
                /^::.*/m,
                {
                    pattern: /\bREM\b.*/i,
                    greedy: true
                }
            ],
            'string': {
                pattern: /"[^"]*"/,
                greedy: true
            },
            'variable': /%[~dp]*(?:\d|[a-zA-Z_]\w*)%?/,
            'label': {
                pattern: /^:[^\s:].*/m,
                alias: 'keyword'
            },
            'number': /\b\d+\b/,
            'operator': /[<>|&]/
        };
    }
    // Alias: ```cmd → batch
    Prism.languages.cmd = Prism.languages.batch;

    // =========================================================================
    // CUSTOM LANGUAGE: Metasploit Console (```msf)
    // =========================================================================

    Prism.languages.msf = {
        'comment': {
            pattern: /#.*/,
            greedy: true
        },
        'string': {
            pattern: /"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'/,
            greedy: true
        },
        'prompt': {
            pattern: /^(?:msf\d?|meterpreter)(?:\s+\S+\([^)]*\))?\s*>\s?/m,
            alias: 'keyword'
        },
        'status': {
            pattern: /^\[[\*\+\-!]\]/m,
            alias: 'punctuation'
        },
        'number': /\b\d+(?:\.\d+){0,3}\b/
    };

    // =========================================================================
    // CUSTOM LANGUAGE: Cobalt Strike Beacon Console (```beacon)
    // =========================================================================

    Prism.languages.beacon = {
        'comment': {
            pattern: /#.*/,
            greedy: true
        },
        'string': {
            pattern: /"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'/,
            greedy: true
        },
        'prompt': {
            pattern: /^beacon\s*>/m,
            alias: 'keyword'
        },
        'command': {
            // Longer alternatives first to prevent partial matches
            pattern: /\b(?:execute-assembly|inline-execute|powershell-import|kerberos_ticket_use|kerberos_ticket_purge|rportfwd_local|remote-exec|token-store|data-store|steal_token|make_token|runasadmin|logonpasswords|chromedump|powerpick|powershell|blockdlls|covertvpn|getsystem|rportfwd|portscan|hashdump|download|spawnto|spawnas|spawnu|elevate|connect|jobkill|mimikatz|rev2self|ssh-key|checkin|drives|execute|cancel|dcsync|runas|sleep|shell|socks|shell|mkdir|mode|link|jump|runu|ppid|jobs|pth|ssh|run|pwd|cd|ls|cp|mv|rm|upload|unlink|getuid)\b/,
            alias: 'function'
        },
        'number': /\b\d+(?:\.\d+)?\b/
    };

    // =========================================================================
    // CUSTOM LANGUAGE: C2 Framework Consoles (```c2)
    //   Covers: Sliver, Havoc (Demon), dnscat2
    // =========================================================================

    Prism.languages.c2 = {
        'comment': {
            pattern: /#.*/,
            greedy: true
        },
        'string': {
            pattern: /"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'/,
            greedy: true
        },
        'prompt': {
            // sliver >, sliver (IMPLANT) >, demon >, dnscat2 >, command (client) >
            pattern: /^(?:sliver(?:\s+\([^)]*\))?|demon|dnscat2|command\s+\([^)]*\))\s*>/m,
            alias: 'keyword'
        },
        'command': {
            pattern: /\b(?:execute-assembly|inline-execute|dotnet|shellcode|socks5|portfwd|generate|profiles|implants|sessions|beacons|background|rename|armory|hashdump|migrate|pivots|whoami|getuid|getpid|ifconfig|netstat|download|upload|execute|shell|powershell|config|sleep|token|socks|mkdir|lsass|jump|info|jobs|mtls|https|dns|wg|use|cat|dir|env|ps|ls|cd|rm|cp|mv|pwd|listen|session)\b/,
            alias: 'function'
        },
        'number': /\b\d+(?:\.\d+)?\b/
    };

    // =========================================================================
    // CUSTOM LANGUAGE: Mimikatz Console (```mimikatz)
    // =========================================================================

    Prism.languages.mimikatz = {
        'comment': {
            pattern: /^#(?!.*::).*/m,
            greedy: true
        },
        'prompt': {
            pattern: /^mimikatz#/m,
            alias: 'keyword'
        },
        'module-command': {
            // module::command syntax (sekurlsa::logonpasswords, kerberos::golden, etc.)
            pattern: /\b(?:sekurlsa|lsadump|kerberos|token|vault|dpapi|privilege|crypto|net|event|misc|ts|process|service|sid|busylight|sysenv|minesweeper)::\w+/,
            alias: 'function'
        },
        'parameter': {
            // /flag:value parameters
            pattern: /\/\w+(?::[^\s]+)?/,
            alias: 'property'
        },
        'number': /\b\d+(?:\.\d+)?\b/
    };

    // =========================================================================
    // PRISM HOOK
    // =========================================================================

    Prism.hooks.add('complete', function(env) {
        // Bash / Shell / Sh code blocks
        if (env.language === 'bash' || env.language === 'shell' || env.language === 'sh') {
            highlightBareText(env.element, [
                [secTools,    'function'],
                [sysCommands, 'function']
            ]);
        }

        // PowerShell code blocks
        if (env.language === 'powershell') {
            highlightBareText(env.element, [
                [psCommands,  'function'],
                [secTools,    'function'],
                [sysCommands, 'function']
            ]);
        }

        // Windows CMD / Batch code blocks
        if (env.language === 'batch' || env.language === 'cmd') {
            highlightBareText(env.element, [
                [secTools,    'function'],
                [sysCommands, 'function']
            ]);
        }

        // PHP / Ruby / Python / Perl code blocks
        // Highlight tool names that appear in these language blocks
        if (env.language === 'php' || env.language === 'ruby' ||
            env.language === 'python' || env.language === 'perl') {
            highlightBareText(env.element, [
                [secTools,    'function'],
                [sysCommands, 'function']
            ]);
        }

        // Metasploit console blocks
        if (env.language === 'msf') {
            highlightBareText(env.element, [
                [msfKeywords, 'keyword'],
                [secTools,    'function'],
                [sysCommands, 'function']
            ]);
        }
    });

})();
