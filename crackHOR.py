#!/usr/bin/python
#Version: crackHORv1.2
#Author: Craig Freyman
#Change log:
#	08/19/2013: Added spin_cycle() function
#	08/26/2013: More spin_cycle fixes
#	10/02/2013: fixed the grep -vi issues on the cut up
#	12/04/2013: Added user,hash,pass compiled list function => create_final_list()
from __future__ import division
import subprocess,sys,os,fnmatch,platform,fileinput,re,difflib,shutil

def main():
	validate_file_folder_loc()
	clean_up()
	backup_file()
	check_and_cut()
	sort_and_dedupe()	
	hashcat_wordlists()
	hashcat_wordlist_with_rules()
	remove_cracked_hashes()
	#if lm_option in ("L","l"):
	#hashcat_LM()
	#rcrack_tables()
	ophcrack_lm_tables()
	hashcat_patterns()
	compile_all_passwords()
	merge_with_master()
	create_final_list()

def validate_file_folder_loc():
	#This function validates the file/folder locations specified in main()
	#rcrack_table_loc_ver = os.path.exists(rcrack_table_location)
	ophcrack_table_loc_ver = os.path.exists(ophcrack_table_location)
	rcrack_location_ver =  os.path.exists(rcrack_location)
	hashcat_location_ver = os.path.exists(hashcat_location)
	wordlist_folder_ver = os.path.exists(wordlist_folder)
	master_hor_file_ver = os.path.exists(master_hor_file)
	master_hor_ext_backup_ver = os.path.exists(master_hor_ext_backup)
	hashcat_plus_binary_ver = os.path.exists(hashcat_plus_binary)
	hashcat_plus_folder_ver = os.path.exists(hashcat_plus_folder)

	#if rcrack_table_loc_ver is False:
	#	print "[-] "+rcrack_table_location+ " is an invalid path."
	#	sys.exit(0)

	if ophcrack_table_loc_ver is False:
		print "\033[1;31m[-] "+ophcrack_table_location+ " is an invalid path.\033[1;m\n"
		sys.exit(0)

	if rcrack_location_ver is False:
		print "\033[1;31m[-] "+rcrack_location+ " is an invalid path.\033[1;m\n"
		sys.exit(0)

	if hashcat_location_ver is False:
		print "\033[1;31m[-] "+hashcat_location+ " is an invalid path.\033[1;m\n"
		sys.exit(0)

	if wordlist_folder_ver is False:
		print "\033[1;31m[-] "+wordlist_folder+ " is an invalid path.\033[1;m\n"
		sys.exit(0)
		
	if hashcat_plus_binary_ver is False:
		print "\033[1;31m[-] "+hashcat_plus_binary+ " is an invalid path.\033[1;m\n"
		sys.exit(0)
		
	if hashcat_plus_folder_ver is False:
		print "\033[1;31m[-] "+hashcat_plus_folder+ " is an invalid path.\033[1;m\n"
		sys.exit(0)

	if master_hor_file_ver is False:
		cont = raw_input("\033[1;31m[-] "+master_hor_file+ " does not exist. Create it now?\033[1;m\n")
		if "Y" or "y" in cont:
			os.system("touch "+master_hor_file)
		else:
			sys.exit(0)
			
	if master_hor_ext_backup_ver is False:
		print "\033[1;31m[-] Can't get to "+master_hor_ext_backup+ " exiting... \033[1;m\n"
		sys.exit(0)
def clean_up():
	#This function looks to see if the script has already run and deletes the two folders created by it. Then it calls the merger passwords functions.
	dirlist = os.listdir(".")
	workingdir = "working_files"
	crackeddir = "cracked_passwords"
	#remove hashcat.dicstat file
	os.system("rm "+hashcat_plus_folder+"/hashcat.dictstat")
	if workingdir in dirlist:
		#If we find existing directories, lets compile and merge any passwords in limbo to the master file. 
		print "\033[1;31m[-] Found existing working directories.\033[1;m"
		#if os.path.exists("cracked_passwords/ophcrack.hashandpw.tmp"):
		#	print "\033[1;34m[-] Below are hashes I don't know what to do with. Manually add them to "+master_hor_file+"\033[1;m"
		#	print "\033[1;34m[-] Refer to --> cracked_passwords/ophcrack.hashandpw.tmp\033[1;m"
		#	raw_input("\033[1;34m[-] Press ENTER to LESS the file...\033[1;m")
		#	os.system("less cracked_passwords/ophcrack.hashandpw.tmp")
		if os.path.exists("cracked_passwords/lm.passwords.tmp"):
			print "\033[1;34m[-] Below are hashes I don't know what to do with. Manually add them to "+master_hor_file+"\033[1;m"
			print "\033[1;34m[-] Refer to --> cracked_passwords/lm.passwords.tmp\033[1;m"
			raw_input("\033[1;34m[-] Press ENTER to LESS the file...\033[1;m")
			os.system("less cracked_passwords/lm.passwords.tmp")
		
		#if lm.passwords is there, lets run the toggle attack to finish
		if os.path.exists("cracked_passwords/lm.passwords"):
			lm_toggle_case()
			
		
		#compile and merge anything that is there
		compile_all_passwords()
		merge_with_master()
		answer = raw_input("\033[1;34m[-] Do you want to see a list of the discovered passwords from last session?\033[1;m")
		if answer in ("Y","y"):
			create_final_list()
		while True:
			delwork = raw_input("\033[1;31m[-] "+workingdir+" exists. Delete? (Y/n) \033[1;m")
			if delwork in ("N","n"):
				break
			if delwork in ("y","Y"):
				shutil.rmtree("working_files/")
				log_file.write("[*] Clean_up() function deleted the working_files folder.")
				break
			if delwork not in ("Y","y","N","n"):
                                print "\033[1;31m[-] Please press y or n \033[1;m"

	if crackeddir in dirlist:
		while True:
			delcrack = raw_input("\033[1;31m[-] "+crackeddir+" exists. Delete? (Y/n) \033[1;m")
			if delcrack in ("N","n"):
				break
	        	if delcrack in ("y","Y"):
				shutil.rmtree("cracked_passwords/")
				log_file.write("[*] Clean_up() deleted the cracked_passwords folder.")
				break
			if delcrack not in ("Y","y","N","n"):
				print "\033[1;31m[-] Please press y or n \033[1;m"
				
def backup_file():
	#This function backs up the original hash file and creates our working directories.
	#Created file: working_files/<hash file>.original
	try:
		os.makedirs("working_files")
		os.makedirs("cracked_passwords")
	except:
		pass
	try: 
		os.system("cp " +hash_file+" working_files/hashfile.original")
		#print "\033[1;32m[*] Backed up original hash file: "+hash_file+" to working_files/"+hash_file+".original\033[1;m"
		os.system("cp " +master_hor_file+ " "+master_hor_ext_backup)
		#print "\033[1;32m[*] Backed up master file to external media.\033[1;m"
		log_file.write("[*] Backupfile() backed up "+hash_file+" to: working_files/"+hash_file+".original\n")
		log_file.write("[*] Backupfile() backed up "+master_hor_file+" to: "+master_hor_ext_backup)
	except Exception, e:
		print "[-] Backup_file() had a problem. Exiting..."
		print e
		log_file.write("[-] Backup_file had a problem. Exiting...")
		sys.exit(0)
	#raw_input("\033[1;32m[*] Done backing up files, press ENTER to continue...\033[1;m")

def check_and_cut():
	#This function makes a weak attempt at verifying the original file is in PWDUMP format. 
	#Then it removes the machine$ and IUSR_ hashes out.
	#Finally, it creates two files for further processing.
	#Created files: working_files/inputfile.no.machine 
	#		working_files/lm_ntlm.ophcrack 
	#		working_files/ntlm.hashcat
	counter = 1
	
	for line in fileinput.input(hash_file):
	#	line = line.lstrip()
		pwdump_format = re.search(r'[a-zA-Z0-9\*\s]{32}:[a-zA-Z0-9\*\s]{32}:::',line,re.M)
	#	if pwdump_format is None:
	#		print "\033[1;31m[-] Line "+str(counter)+" might be bad.\033[1;m"
	#	counter +=1
	
	if pwdump_format is None:
		print "\033[1;31m[-] This file might not be in PWDUMP format. The rest of this might fail.\033[1;m"
		log_file.write("[*] Check_and_cut() function thinks the original input file might have issues.\n")
	
	#If the file looks good, pull out machine accounts and create a lm_ntlm.ophcrack and a ntlm.hashcat file
	#print "\033[1;32m[*] Creating Ophcrack file in LM:NTLM format and NTLM format for hashcat. Also removing machine accounts.\033[1;m"
	print "\033[1;34m-----------------------------------------------------------\033[1;m"
	print "\033[1;31m| Number of Starting Hashes  \t\t"+str(count_lines(hash_file))+"\t\n\033[1;m"

	try:

		#os.system("grep -vi ASPNET "+hash_file+" > working_files/inputgrep.noaspnet")
		#os.system("grep -vi \\\\$ "+hash_file+" > working_files/inputgrep.nomachine")
		#os.system("grep -vi IUSR_ "+hash_file+"> working_files/inputgrep.noiusr")
		#os.system("cat working_files/inputgrep* > working_files/inputfile.no.machine")
		os.system("cat "+hash_file+" | grep -vi ASPNET | grep -vi \\\\$ | grep -vi IUSR_ > working_files/inputfile.no.machine")
		os.system("cut -d : -f3,4 working_files/inputfile.no.machine > working_files/lm_ntlm.ophcrack.tmp")
		#Remove all the LM hashes that have NO PASSWORD in them.
		os.system("cat working_files/lm_ntlm.ophcrack.tmp | grep -vi 'NO PASSWORD*********************' | grep -vi 'aad3b435b51404eeaad3b435b51404ee' | grep -vi '00000000000000000000000000000000' > working_files/lm_ntlm.ophcrack")
		os.system("cut -d : -f4 working_files/inputfile.no.machine > working_files/ntlm.hashcat")
		log_file.write("[*] Check_and_cut() sucessfully cut all files.\n")
	except:
		print "[-] Check_and_cut() had a problem. Exiting...\n"
		log_file.write("[-] Check_and_cut() had a problem. Exiting...\n")
		sys.exit(0)

	first_count = count_lines(hash_file)
	second_count_oph = count_lines("working_files/lm_ntlm.ophcrack")
	second_count_hashcat = count_lines("working_files/ntlm.hashcat")
	diff_oph = first_count - second_count_oph
	diff_hash = first_count - second_count_hashcat
	
	print "\033[1;34m| Non User Accounts Removed \tLM: \t"+ str(diff_oph)+"\n|\t\t\t\tNTLM: \t"+str(diff_hash)+"\t\033[1;m" 
	

def sort_and_dedupe():
	#This function sorts and deduplicates lm_ntlm.ophcrack and ntlm.hashcat. It outputs two files.
	#Created files: working_files/lm_ntlm.ophcrack.deduped
	#		working_files/ntlm.hashcat.deduped
	
	firstfile_count = count_lines('working_files/lm_ntlm.ophcrack')
	os.system("sort working_files/lm_ntlm.ophcrack -u > working_files/lm_ntlm.ophcrack.deduped")
	secondfile_count = count_lines("working_files/lm_ntlm.ophcrack.deduped")
	difference1 = firstfile_count - secondfile_count
	
	log_file.write("[+] Sort_and_dedupe() removed "+str(difference1)+" duplicates from lm_ntlm.ophcrack\n")
	firstfile_count = count_lines('working_files/ntlm.hashcat')
	os.system("sort working_files/ntlm.hashcat -u > working_files/ntlm.hashcat.deduped")
	secondfile_count = count_lines("working_files/ntlm.hashcat.deduped")
	difference2 = firstfile_count - secondfile_count
	print "\033[1;34m| Duplicates Removed\t\tLM: \t"+str(difference1)+"\n|\t\t\t\tNTLM: \t"+str(difference2)+"\033[1;m"
	log_file.write("[+] Sort_and_dedupe() removed "+str(difference2)+" duplicates from ntlm.hashcat\n")
	raw_input("\033[1;32m| Hashes Left to Crack \t\tLM:\t"+str(count_lines("working_files/lm_ntlm.ophcrack.deduped"))+ "\n|\t\t\t\tNTLM:\t"+str(count_lines("working_files/ntlm.hashcat.deduped"))+"\n|\n| \t\tPress ENTER to continue...\n|\t\t      crackHOR "+version+"\n-----------------------------------------------------------\033[1;m") 

def count_lines(somefile):
	#A simple function that counts the lines in a file.

	numlines = 0
	for line in open(somefile):
		numlines += 1
	return numlines

def spin_cycle():
	c = 0.0
	file_exists = os.path.exists("cracked_passwords/hashcatPlus.hashandpw")
        if file_exists is True:
		a = count_lines("cracked_passwords/hashcatPlus.hashandpw")
		b = count_lines("working_files/ntlm.hashcat.deduped")
		c = a/b
		if c >= .01:
			print "c is " + str(c)
			print "hashcatPlus.hashandpw file has " +str(a)+" lines"
			print "ntlm.hashcat.deduped file has " +str(b)+" lines"
			raw_input("\n\033[1;32mAbout to hit the hashcat rules again. Continue?\033[1;m")
			remove_cracked_hashes()
			hashcat_wordlist_hor_only()

def hashcat_wordlists():
	#This function takes ntlm.hashcat.dedup and runs it through the straight hashcat wordslist attack to pull out passwords we already have.
	#Creates file: cracked_passwords/hashcat.hashandpw

	print "\033[1;32m[*] Hashcat wordlist mode\033[1;m"
	try:
		os.system(hashcat_location+" --hash-mode 1000 --remove -o cracked_passwords/hashcat.hashandpw working_files/ntlm.hashcat.deduped "+wordlist_folder)
		log_file.write("[*] Hashcat_wordlists() was successful.\n")
	except Exception,e:
		print "[-] Hashcat_wordlists() had a problem. Exiting...\n"
		print e
		log_file.write("[-] Hashcat_wordlists() had a problem. Exiting...\n")
		sys.exit(0)

def hashcat_wordlist_hor_only():
		compile_all_passwords()
		merge_with_master()
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove -r "+hashcat_plus_folder+"rules/passwordspro.rule --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped "+master_hor_file)
		#raw_input("just ran spincycle on master_hor.txt")	

def hashcat_wordlist_with_rules():
	#This function takes ntlm.hashcat.dedup and runs the GPU hashcatPlus rule attacks.
	print "\033[1;32m[*] Hashcat wordlist WITH rules mode\033[1;m"
	try:
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove -r "+hashcat_plus_folder+"rules/toggles1.rule -r "+hashcat_plus_folder+"rules/toggles2.rule -r "+hashcat_plus_folder+"rules/toggles3.rule -r "+hashcat_plus_folder+"rules/toggles4.rule -r "+hashcat_plus_folder+"rules/toggles5.rule -r "+hashcat_plus_folder+"rules/passwordspro.rule --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped "+master_hor_file)
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove -r "+hashcat_plus_folder+"rules/"+rules+" --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped "+master_hor_file+ " "+hashcat_plus_rules_wordlists)
		spin_cycle()

	except Exception,e:
                print "[-] Hashcat_wordlist_with_rules() had a problem. Exiting...\n"
                print e
                log_file.write("[-] Hashcat_wordlist_with_rules() had a problem. Exiting...\n")
                sys.exit(0)



def remove_cracked_hashes():
	#This function removes the discovered hashes in hashcat.hashandpw from lm_ntlm.ophcrack.deduped. Reason being, our next attack will utilize ophcrack, which uses an input file in a different format.
	#Creates files:	working_files/hashcat.hashandpw.uniq
	#		working_files/hashcat.hashandpw.uniq.upper
	#		working_files/lm_ntlm.ophcrack.deduped.upper
	#		working_files/lm_ntlm.ophcrack.deduped.ready
	
	print "\033[1;32m[*] Removing cracked hashes in hashcat.hashandpw from Ophcrack file\033[1;m"
	os.system("cat cracked_passwords/*.hashandpw |sort | cut -d : -f1 | uniq > working_files/hashcat.hashandpw.uniq")

	#Convert the hashes to uppercase because hashcat puts them in lower
	f1 = open('working_files/hashcat.hashandpw.uniq','r')
	f2 = open('working_files/hashcat.hashandpw.uniq.upper','w')
	for line in f1:
		line = line.lstrip()
		f2.write(line.upper())
	f1.close()
	f2.close()

	#Do the same with this file, just in case
	f3 = open('working_files/lm_ntlm.ophcrack.deduped','r')
	f4 = open('working_files/lm_ntlm.ophcrack.deduped.upper','w')
	for line in f3:
		line = line.lstrip()
		f4.write(line.upper())
	f3.close()
	f4.close()

	#Store all the discovered hashcat hashes in a set which we reference later
	with open("working_files/hashcat.hashandpw.uniq.upper", "r") as f1:
		keys = set(f1.read().splitlines())

	#Search through lm_ntlm.ophcrack.deduped line by line, referencing the set above.
	#If there is a match, do nothing. If there isnt a match, that means the password still needs to be cracked so write that line to a new file.
	with open("working_files/lm_ntlm.ophcrack.deduped.upper", "r") as f2:
		with open("working_files/lm_ntlm.ophcrack.deduped.ready", "w") as dest:
        		for line in f2:
				line = line.strip()
				try:
					if line.split(":")[1] in keys:
			                	log_file.write("[*] Remove_hashes() "+line+" found, ignoring.\n")
					else:
			                	dest.write(line+"\n")
						log_file.write("[*] Remove_hashes() "+line+" not found sent to Ophcrack.\n")
				except:
					continue
	
	#This file will be used for the lm hash attack	
	os.system("cut -d : -f1 working_files/lm_ntlm.ophcrack.deduped.ready > working_files/lm.hashes")
	
def hashcat_LM():
	empty_hash = "AAD3B435B51404EE"
	with open("working_files/lm.hashes", "r") as f1:
		for line in f1:
			chunk1 = line[0:16]
			chunk2 = line[16:32]
			if empty_hash in chunk1 and chunk2:
				print "breaking out"
				break
			#The LM toggle case attack
			#Hashcat return codes:
			#0 = cracked 
			#1 = not cracked 
			#255 = weak hash
			
			#status1 = subprocess.Popen(hashcat_plus_binary+" --hash-type 3000 --outfile-format=2 --outfile working_files/hashcatPlusLM.lmpass "+chunk1+" -a 3 ?u?u?u?u?u?u?u --force --increment",shell=True).wait()
			#status2 = subprocess.Popen(hashcat_plus_binary+" --hash-type 3000 --outfile-format=2 --outfile working_files/hashcatPlusLM.lmpass "+chunk2+" -a 3 ?u?d?d?d?d?d?d --force --increment",shell=True).wait()
			
			#brute force blaster
			status1 = subprocess.Popen(hashcat_plus_binary+" --hash-type 3000 --outfile-format=2 --outfile working_files/hashcatPlusLM.lmpass "+chunk1+" -a 3 -1 charsets/lm.charset --force --increment --increment-max=7",shell=True).wait()
			status2 = subprocess.Popen(hashcat_plus_binary+" --hash-type 3000 --outfile-format=2 --outfile working_files/hashcatPlusLM.lmpass "+chunk2+" -a 3 -1 charsets/lm.charset --force --increment --increment-max=7",shell=True).wait()

				
			#if both are cracked then write to file
			if status1 is 0 and status2 is 0:
				f = open("working_files/hashcatPlusLM.lmpass")
				linelist = f.readlines()
				f.close()
				pass1 = linelist[-2]
				pass2 = linelist[-1]
				lmpass = pass1.strip()+pass2.strip()
				f2 = open("cracked_passwords/lm.passwords", "a")
				f2.write(lmpass+"\n")
				f2.close()

			#if first part is cracked and second is empty, write to file
			elif status1 is 0 and status2 is 255:
				f = open("working_files/hashcatPlusLM.lmpass")
				linelist = f.readlines()
				f.close()
				pass1 = linelist[-1]
				lmpass = pass1.strip()
				f2 = open("cracked_passwords/lm.passwords", "a")
				f2.write(lmpass+"\n")
				f2.close()

			#if both are not cracked, write to file 
			elif status1 is 1 and status2 is 1:
				f4 = open("working_files/lm_not_cracked.txt", "a")
				f4.write("NothingCracked:"+line)
				f4.close()

			#if first is not cracked and second is empty
			elif status1 is 1 and status2 is 255:
				f5 = open("working_files/lm_not_cracked.txt", "a")
				f5.write("NothingCracked:"+line)
				f5.close()

			#if first is not cracked and second is cracked	
			elif status1 is 1 and status2 is 0:
				f3 = open("working_files/lm_not_cracked.txt", "a")
				f3.write("1stHNotCracked:"+chunk1+":"+line)
				f3.close()

			#if first is not cracked and second is empty
			elif status1 is 1 and status2 is 255:
				f6 = open("working_files/lm_not_cracked.txt", "a")
				f6.write("1stHNotCracked:"+chunk1+":"+line)
				f6.close()

			#if first is cracked but second is not cracked
			elif status1 is 0 and status2 is 1:
				f3 = open("working_files/lm_not_cracked.txt", "a")
				f3.write("2ndHNotCracked:"+chunk2+":"+line)
				f3.close()				
		
	lm_toggle_case()
	remove_cracked_hashes()

def lm_toggle_case():
	#after we're done with all the hashes, run the toggle case attack on them all to get the real password.
	#os.system(hashcat_location+" -m 1000 -o cracked_passwords/lm_attack.hashandpw -a 2 working_files/ntlm.hashcat.deduped cracked_passwords/lm.passwords")
	os.system(hashcat_plus_binary+" --hash-type 1000 --remove -r "+hashcat_plus_folder+"rules/passwordspro.rule --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped cracked_passwords/lm.passwords")
		
def ophcrack_lm_tables():
	#raw_input()
	#This function takes the trimmed down lm_ntlm.ophcrack.deduped.ready and sends it through the XP_Special tables in ophcrack.
	#Creates file: cracked_passwords/ophcrack.out
	#print "\033[1;32m[*] Ophcrack LM table mode\033[1;m"
	try:
		#Ophcrack recommends to change the number of threads to 1 more than the amount of cores on the CPU --> -n option
		os.system("ophcrack -g -n 5 -e -d "+ophcrack_table_location+" -t XP_special -f working_files/lm_ntlm.ophcrack.deduped.ready -S working_files/ophcrack.session -o cracked_passwords/ophcrack.out")
		log_file.write("[*] Ophcrack_lm_tables() was successful.\n")
	except:
		print "[-] Ophcrack_lm_tables() had a problem. Exiting...\n"
		log_file.write("[-] Ophcrack_lm_tables() had a problem. Exiting...\n")
		sys.exit(0)

def hashcat_patterns():
 	print "\033[1;32m[*] Hashcat patterns attack\033[1;m"
        try:

		os.system(hashcat_plus_binary+" --hash-type 1000 --remove --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped --force -a 3 ?s?u?l?l?l?l?l?l")
               	os.system(hashcat_plus_binary+" --hash-type 1000 --remove --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped --force -a 3 ?d?d?u?l?l?l?l?l")
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped --force -a 3 ?d?u?l?l?l?l?l?l")
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped --force -a 3 ?u?l?l?l?l?l?d?s")
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped --force -a 3 ?u?l?l?l?l?l?d?d")
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped --force -a 3 ?u?l?l?l?l?l?l?d?d")
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped --force -a 3 ?u?l?l?l?l?d?d?d?d")
		os.system(hashcat_plus_binary+" --hash-type 1000 --remove --outfile cracked_passwords/hashcatPlus.hashandpw  working_files/ntlm.hashcat.deduped --force -a 3 ?u?l?l?l?l?l?l?l?d")


        except Exception,e:
                print "[-] Hashcat_patterns() had a problem. Exiting...\n"
                print e
                log_file.write("[-] Hashcat_patterns() had a problem. Exiting...\n")
                sys.exit(0)	


def rcrack_tables():
	#This function takes the outputted file from ophcrack_lm_tables(), cuts it up outputs the NTLM hashes that have not been cracked to a new file, ready for rcrack. Uncracked hashes have the ::: in them.
	#Creates files: working_files/rcrack.ready
	#				cracked_passwords/rcrack.out
	print "\033[1;32m[*] Rcrack NTLM table mode\033[1;m"
	try:
		os.system("awk -F ':::' '{ print $2 }' cracked_passwords/ophcrack.out | sort -u > working_files/rcrack.ready")
		os.system("awk -F '::' '{ print $2 }' cracked_passwords/ophcrack.out | sort -u > working_files/rcrack.tmp")
		os.system("cut -d : -f2 working_files/rcrack.tmp | sort -u >> working_files/rcrack.ready")
		os.system(rcrack_location+" -l working_files/rcrack.ready -t2 "+rcrack_table_location+" -o cracked_passwords/rcrack.out")
		log_file.write("[*] Rcrack_tables() was successful.\n")
	except:
		print "[-] Rcrack_tables() had a problem. Exiting...\n"
		log_file.write("[-] Rcrack_tables() had a problem. Exiting...\n")
		sys.exit()

def find_bad_chars():
	#Both ophcrack and hashcat have problems when there are colons in the password.
	#This function looks for them and puts them into another file for the user to look at.
	count1 = 0
	count2 = 0
	try:
		with open("cracked_passwords/ophcrack.out", "r") as f5:
			with open("cracked_passwords/ophcrack.hashandpw.tmp", "w") as dest:
				for line in f5:
					line = line.strip()  
					if ":::" in line:
					        continue
					else:
						if "\xc1" in line:
							print "[-] Found bad ophcrack chars. Look at cracked_passwords/ophcrack.hashandpw.tmp manually"
							line = 	line.replace("\xc1",":")
							dest.write(line+"\n")
							count1+=1
														
						else:
							continue
	except:
		pass
	if count1 == 0:
		tmp1 = os.path.exists("cracked_passwords/ophcrack.hashandpw.tmp")	
		if tmp1 is True:
			os.system("rm cracked_passwords/ophcrack.hashandpw.tmp")
	try:
		with open("cracked_passwords/lm.passwords", "ra") as source:
			with open("cracked_passwords/lm.passwords.tmp", "w") as dest:
				for line in source:
					#print "HERE WE ARE"
					line = line.strip()  
					if "\x9c" in line:
						print "[-] Found bad hashcat chars. Look at cracked_passwords/lm.passwords.tmp"
						newline = line.replace("\x9c",":")
						dest.write(newline+"\n")
						count2+=1

	except:
		pass

	if count2 == 0:
        	tmp2 = os.path.exists("cracked_passwords/lm.passwords.tmp")
                if tmp2 is True:
                        os.system("rm cracked_passwords/lm.passwords.tmp")

def compile_all_passwords():
	#This function takes all the cracked passwords and compiles them into a single file.
	#Since ophcrack outputs into a different format, we have to clean up the file first.
	
	find_bad_chars()	

	#devnull = open('/dev/null', 'w')
	os.system("cut -d : -f7- cracked_passwords/ophcrack.out |sort -u > cracked_passwords/ophcrack.pwonly")
	os.system("cut -d : -f2 cracked_passwords/rcrack.out |sort -u > cracked_passwords/rcrack.pwonly")
	os.system("cut -d : -f1,2 cracked_passwords/rcrack.out | sort -u > cracked_passwords/rcrack.hashandpw")
	os.system("cut -d : -f2- cracked_passwords/hashcat.hashandpw |sort -u > cracked_passwords/hashcat.pwonly")
	os.system("cut -d : -f2- cracked_passwords/lm_attack.hashandpw  |sort -u > cracked_passwords/hashcatLM.pwonly")
	os.system("cut -d : -f2- cracked_passwords/hashcatPlus.hashandpw  |sort -u > cracked_passwords/hashcatPlus.pwonly")
	oph_bad_char_file = os.path.exists("cracked_passwords/ophcrack.hashandpw.tmp")
	if oph_bad_char_file is True:
		os.system("cut -d : -f8- cracked_passwords/ophcrack.hashandpw.tmp |sort -u > cracked_passwords/ophcrack2.pwonly")
	os.system("cat cracked_passwords/*.pwonly |sort -u > cracked_passwords/final.pwonly")
	os.system("cat cracked_passwords/*.hashandpw |sort -u > cracked_passwords/final.hashandpw")
	
	
	
def merge_with_master():
	#This function copies the master password file into working_files. Then we cat our final.pwonly file with that file and sent it back to
	#the wordlist location. Only the changes are saved.
	os.system("cp "+master_hor_file+" working_files/master_hor_pre.txt")		
	file_is_there = os.path.exists("cracked_passwords/final.pwonly")
	if file_is_there is True:
		os.system("cat cracked_passwords/final.pwonly working_files/master_hor_pre.txt | sort -u > working_files/tempcount.txt")
		firstfile_count = count_lines("working_files/tempcount.txt")
		secondfile_count = count_lines("working_files/master_hor_pre.txt")
		difference = firstfile_count - secondfile_count
		if difference > 0:
			os.system("cat cracked_passwords/final.pwonly working_files/master_hor_pre.txt | sort -u >  "+master_hor_file)
			print "\033[1;34m[+] There were "+str(difference)+" new passwords added to your master file: "+master_hor_file+"\033[1;m"
			log_file.write("[*] Merge_with_master() says there were "+str(difference)+" new passwords added to your master file: "+master_hor_file+"\n")
	else:
		print "\033[1;32m[-] No final.pwonly found.\033[1;m"

def create_final_list():
	counter = 0
	raw_input( "\033[1;34m[+] Press ENTER to see a list of the cracked creds.\033[1;m")
	os.system("cut -d : -f1,4 working_files/hashfile.original > working_files/details.txt")
	file1='working_files/details.txt'
	file2='cracked_passwords/final.hashandpw'
	file3='cracked_passwords/final.hashandpwandusername'
	
	with open(file3,"w") as final:
		with open(file1,"r") as f1:
        		for line1 in f1:
                		with open(file2,'r') as f2:
                        		for line2 in f2:
                                		if line2[:32].rstrip() in line1[-33:].rstrip():
                                        		result= line1.rstrip() +"<==>"+  line2.rstrip()
							print result
							final.write(result+"\n")
							counter+=1
	
	print ("\033[1;34m[+] Cracked "+str(counter)+" passwords. An output file with usernames, passwords and hashes can be found in => cracked_passwords/final.hashandpwandusername \033[1;m")


	
if __name__ == '__main__':
	#Specify the locations of all your stuff

	rcrack_table_location = "/media/DATA/labsshare/rcracki_rainbow_tables/ntlm_mixalpha-numeric#1-8_*/"
	ophcrack_table_location = "/coalfire/cracking/ophcrack_rainbow_tables"
	rcrack_location =  "/coalfire/cracking/rcracki_mt_.7_beta_cuda/./rcracki_mt"
	hashcat_plus_binary = "/coalfire/cracking/hashcat/oclHashcat-plus-0.15/./cudaHashcat-plus64.bin"
	hashcat_plus_folder = "/coalfire/cracking/hashcat/oclHashcat-plus-0.15/"
	hashcat_location = "/coalfire/cracking/hashcat/hashcat-0.46/./hashcat-cli64.bin"
	wordlist_folder = "/coalfire/cracking/wordlists/"
	#wordlist_folder = "/media/data/crack/pword-list/"
	hashcat_plus_rules_wordlists = "/coalfire/cracking/wordlists/"
	master_hor_file = "/coalfire/cracking/wordlists/master_hor.txt"
	master_hor_ext_backup = "/media/ext_backup/"
	version = "1.2"
	log_file = open("hor.log", "w")
	keep_going = True
	
	if len(sys.argv) < 3:
		print "[+] USAGE:\t./filename <pwdump-file> <hashcat rule i.e. best64.rule>"
		print "[+] Possible rules: best64.rule, perfect.rule, combinator.rule, leetspeak.rule, specific.rule, d3ad0ne.rule, oscommerce.rule, T0XlC.rule, toggles1.rule, toggles2.rule, toggles3.rule, toggles4.rule, generated.rule, passwordspro.rule"
		sys.exit(0)
	if platform.system() == "Windows":
		print "[-] Windows is not supported."
		sys.exit(0)
	is_root = os.geteuid()
	if is_root is not 0:
		print "[-] Please run as root"
		sys.exit(0)
	try:
		hash_file = sys.argv[1]
		lm_option = sys.argv[2]
		rules = sys.argv[3]
	except:
		hash_file = sys.argv[1]
		rules = sys.argv[2]
	main()
	log_file.close()
