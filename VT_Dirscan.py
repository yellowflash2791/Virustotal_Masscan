#!/usr/bin/python
# This is a simple python script writtern to find the reputation of files on virustotal,this script will help us in scanning all the files
# in a directory and its subdirectories,we can also scan single files and hashes
# Sign into VirusTotal,you will be provided with an api_key,paste the api_key between the double quotes in the field mentioned below and you are good to go
# this script is a property of Arnold Anthony  

import os
import virustotal 
import sys
import argparse

virus = virustotal.VirusTotal("Paste your API_KEY here") # <--------paste your api_key 
upload=sys.argv
parser = argparse.ArgumentParser(description='Virustotal is a great source to find the reputation of suspicious files.We generally upload a single file and check for its reputation,Assume if we have a Directory having many subdirectories and files,it would be difficult to upload files one by one and check for its reputation.Hence to overcome this issue i have writtern a small python script that will give the reputation of all the files in a directory.We can also upload a single file or a hash.This script is cross platform it can run on both windows and linux. ')
parser.add_argument("-d","--directory",help="Scan files in a directory ")
parser.add_argument("-f","--file",help="Scan a file or a hash")
args = parser.parse_args()

def directory():
   
   path=upload[2]
   
   for root,dirs,files in os.walk(path): 
   
       for filename in files:
      
        file_path=os.path.join(root,filename) 
     
    
        analysis=virus.scan(file_path)     

        analysis.join()

        assert analysis.done == True    
        

        print "              VT_Dirscan Report                               "       
        print "--------------------------------------------------------------"    
        print "Report for %s" %(filename)
        print "--------------------------------------------------------------"
        print "- Resource's UID:", analysis.id
        print "- Scan's UID:", analysis.scan_id
        print "- Permalink:", analysis.permalink
        print "- Resource's SHA1:", analysis.sha1
        print "- Resource's SHA256:", analysis.sha256
        print "- Resource's MD5:", analysis.md5
        print "- Resource's status:", analysis.status
        print "- Antivirus' total:", analysis.total
        print "- Antivirus's positives:", analysis.positives
        for antivirus, malware in analysis:
           if malware is not None:
            print
            print "Antivirus:", antivirus[0]
            print "Antivirus' version:", antivirus[1]
            print "Antivirus' update:", antivirus[2]
            print "Malware:", malware             
 
def others():
  suspicious=upload[2]
  analysis=virus.scan(suspicious)     
  analysis.join()

  assert analysis.done == True       
  print "              VT_Dirscan Report                               "
  print "----------------------------------------------------------------------"
  print "Report for %s" %(suspicious)
  print "----------------------------------------------------------------------"
  print "- Resource's UID:", analysis.id
  print "- Scan's UID:", analysis.scan_id
  print "- Permalink:", analysis.permalink
  print "- Resource's SHA1:", analysis.sha1
  print "- Resource's SHA256:", analysis.sha256
  print "- Resource's MD5:", analysis.md5
  print "- Resource's status:", analysis.status
  print "- Antivirus' total:", analysis.total
  print "- Antivirus's positives:", analysis.positives
  
  for antivirus, malware in analysis:
      if malware is not None:
         print
         print "Antivirus:", antivirus[0]
         print "Antivirus' version:", antivirus[1]
         print "Antivirus' update:", antivirus[2]
         print "Malware:", malware             

if args.directory:
   directory()
if args.file:
   others()

