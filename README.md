# VT_Dirscan
Virustotal is a great source to find the reputation of suspicious files.We generally upload a single file and check for its reputation,Assume if we have a Directory having many subdirectories and files,it would be difficult to upload files one by one and check for its reputation.Hence to overcome this issue i have writtern a small python script that will give the reputation of all the files in a directory.We can also upload a single file or a hash.This script is cross platform it can run on both windows and linux.

Installation: 

- Download the files i.e virustotal.pyc and VT_Dirscan.py to a folder or just download the zip file virustotal_masscan.zip
- Sign into Virustotal,on logging in you will get an API_KEY,paste it in the script i.e virus = virustotal.VirusTotal("------------"))
_____________________________________________________________________________________________________________________________

Execution:

1)

python VT_Dirscan.py -h

usage: VT_Dirscan.py [-h] [-d DIRECTORY] [-f FILE]

Virustotal is a great source to find the reputation of suspicious files.We
generally upload a single file and check for its reputation,Assume if we have
a Directory having many subdirectories and files,it would be difficult to
upload files one by one and check for its reputation.Hence to overcome this
issue i have writtern a small python script that will give the reputation of
all the files in a directory.We can also upload a single file or a hash.This
script is cross platform it can run on both windows and linux.

optional arguments:
  -h, --help            show this help message and exit

  -d DIRECTORY, --directory DIRECTORY
                        Scan files in a directory

  -f FILE, --file FILE  Scan a file or a hash
  
2) python VT_Dirscan.py -d /root/Desktop/Exploits/

3) python VT_Dirscan.py -f /root/Desktop/Exploits/exp.pl

4) python VT_Dirscan.py -f c93af9b8f514e299ffe0f01179a41ae2
  _____________________________________________________________________________________________________________________________

Results:

VT_Dirscan Report                               
----------------------------------------------------------------------
Report for /root/Desktop/Exploits/exp.pl
----------------------------------------------------------------------
- Resource's UID: 81d10043a2d94d9ce7554c4500d0172425355c6d93e424b8e1dbf2961f5635bb-1460182114
- Scan's UID: 81d10043a2d94d9ce7554c4500d0172425355c6d93e424b8e1dbf2961f5635bb-1460182114
- Permalink: https://www.virustotal.com/file/81d10043a2d94d9ce7554c4500d0172425355c6d93e424b8e1dbf2961f5635bb/analysis/1460182114/
- Resource's SHA1: af406c8a10726f3aec741e00f352f8c9c3ea2a15
- Resource's SHA256: 81d10043a2d94d9ce7554c4500d0172425355c6d93e424b8e1dbf2961f5635bb
- Resource's MD5: c93af9b8f514e299ffe0f01179a41ae2
- Resource's status: Scan finished, information embedded
- Antivirus' total: 57
- Antivirus's positives: 5

Antivirus: TrendMicro-HouseCall
Antivirus' version: 9.800.0.1009
Antivirus' update: 20160409
Malware: TROJ_Generic

Antivirus: Avast
Antivirus' version: 8.0.1489.320
Antivirus' update: 20160409
Malware: IRC:Malware-gen

Antivirus: TrendMicro
Antivirus' version: 9.740.0.1012
Antivirus' update: 20160409
Malware: TROJ_Generic

Antivirus: McAfee-GW-Edition
Antivirus' version: v2015
Antivirus' update: 20160408
Malware: Perl/Exploit-WordPre

Antivirus: McAfee
Antivirus' version: 6.0.6.653
Antivirus' update: 20160409
Malware: Perl/Exploit-WordPre



