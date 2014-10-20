""" crackHOR2 settings file; all constants should be set here.
"""

# general crackhor settings
VERSION = "2.0"
MASTERHOR_IP = "127.0.0.1"
MASTERHOR_PORT = 8000
# this is the directory we monitor for hash files
MONITOR_DIR = None 
# location of crackHOR2.py
CRACKHOR = None 
# this is where sessions are archived; currently we dont automate this
SESSION_ARCHIVE = None 

# cracking settings for hashcat/ophcrack
HASHCAT_BINARY = None
HASHCAT_DIR = None 
# location of crack wordlists
WORDLIST_DIR = None 
# where sessions are moved to
WORKING_DIR = None 

# monitor.py settings
MONITOR_CHECK = 10

OPHCRACK_TABLES = None 
