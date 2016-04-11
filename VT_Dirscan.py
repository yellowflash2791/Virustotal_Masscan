#!/usr/bin/python
# This is a simple python script writtern to find the reputation of files on virustotal,this script will help us in scanning all the files
# in a directory and its subdirectories,we can also scan single files and hashes
# Sign into VirusTotal,you will be provided with an api_key,paste the api_key between the double quotes in the field mentioned below and you are good to go
# this script is a property of yellow_flash 



import os
import virustotal 

virus = virustotal.VirusTotal("09793033662fcea7eae15c6fd74f7e7034cbc6d4fdfc56eca7bf5486807a740f") # <--------paste your api_key 

def directory():

   path=raw_input("enter the path: ")

   for root,dirs,files in os.walk(path): 
   
       for filename in files:
      
        file_path=os.path.join(root,filename) 
     
    
        analysis=virus.scan(file_path)     

        analysis.join()

        assert analysis.done == True    
     
        print "Report for %s" %(filename)
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
  
  suspicious=raw_input("enter the filepath,Hash that you wanna analyze: ")             

  analysis=virus.scan(suspicious)     

  analysis.join()

  assert analysis.done == True    
     
  print "Report for %s" %(suspicious)
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
 
print "What do you want to upload on VirusTotal"
print "0: Scan the directory and subdirectories in it for malicious files"
print "1: Scan a file or hash"
switch = { 0:directory,
           1:others,
} 
x=input("Enter the option: ")
switch[x]()
