# Virustotal_Masscan
Virustotal is a great source to find the reputation of suspicious files.We generally upload a single file and check for its reputation,Assume if we have a Directory having many subdirectories and files,it would be difficult to upload files one by one and check for its reputation.Hence to overcome this issue i have writtern a small python script that will give the reputation of all the files in a directory.

Installation 

- run the bash script virustotal_masscan.sh
- Sign into Virustotal and get the API_KEY and paste it in the script between the double quotes.(virustotal.VirusTotal("------------"))
_______________________________________________________________________________________________________________________________
Execution

1)

./virustotal_masscan.py

What do you want to upload on VirusTotal

0: Scan the directory and subdirectories in it for malicious files

1: Scan a file or hash

Enter the option: 0

enter the path: /root/Desktop/Exploit

2)

./virustotal_masscan.py

What do you want to upload on VirusTotal

0: Scan the directory and subdirectories in it for malicious files

1: Scan a file or hash

Enter the option: 1

enter the filepath,Hash that you wanna analyze: /root/Desktop/Exploits/exp.pl
_______________________________________________________________________________________________________________________________

Results

Report for /root/Desktop/Exploits/exp.pl
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
