
import binascii
import difflib
import json
import os
import requests
import sys
import time
from copy import deepcopy
from requests import Request, Session
from pprint import pprint
from urlparse import urlparse
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

# Data structure to hold the results
RESULT_KEY_SQLI = "SQL Injection"
RESULT_KEY_SSCI = "Server Side Code Injection"
RESULT_KEY_DIR = "Directory Traversal"
RESULT_KEY_REDIR = "Open Redirect"
RESULT_KEY_CSRF = "CSRF"
RESULT_KEY_CMD = "Command Injection"
RESULT_KEYS = [
	RESULT_KEY_SQLI,
	RESULT_KEY_SSCI,
	RESULT_KEY_DIR,
	RESULT_KEY_REDIR,
	RESULT_KEY_CSRF,
	RESULT_KEY_CMD
]
RESULTS = {result_key: {"class": result_key, "results": {}} for result_key in RESULT_KEYS}

### Scanner configuration and probes ###
CONFIG_TO_SCAN = {
	RESULT_KEY_SQLI: False,
	RESULT_KEY_SSCI: False,
	RESULT_KEY_DIR: False,
	RESULT_KEY_REDIR: False,
	RESULT_KEY_CSRF: False,
	RESULT_KEY_CMD: False
}

CONFIG_USE_FIREFOX = True
CONFIG_REDIR_WAIT = 6

COOKIE_HTTP_HEADER = {'Cookie': 'testcookie'}

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

SSCI_PROBES = [
	"%s",
	"%s.php",
	"../%s",
	"../%s.php",
	"../../%s",
	"../../%s.php"
]

with open('vulnScanScripts/commandInjPayloads.txt') as f:
	commandExecList = list(f)

with open('vulnScanScripts/serverSidePayloads.txt') as f:
	serverInjectList = list(f)

session = Session()

def scan(url, params):
	print("\n[*] Scanning: %s" % url)
	print("[*] Known Params:")
	pprint(params)

	# Parse hostname and endpoint for results file
	parts = urlparse(url)
	hostname = parts.scheme + "://" + parts.netloc
	endpoint = parts.path
	filename = parts.path.split('/')[-1]

	# CSRF
	# ====
	if CONFIG_TO_SCAN[RESULT_KEY_CSRF]:
		print("\n[*] Scanning for CSRF vulnerablities")
		for method in params.keys():
			method_params = params[method]
			auth_response = make_auth_request(method, url, method_params, COOKIE_HTTP_HEADER)
			unauth_response = make_request(method, url, method_params, {'Referer': 'https://www.google.com'})
			# This checks for the case where the CSRF token is a secret cookie (bad implementation)
			if auth_response.content == unauth_response.content:
				print("[!] Authenticated and unauthenticated request produces identical responses")
				print("[*] Note: Ignore unauthenticated only requests as this test case produces false positives")
				add_result(RESULT_KEY_CSRF, hostname, endpoint, method_params, method)

			# This checks for the case where the CSRF token is a hidden form input
			params_copy = deepcopy(method_params)
			deleted_params = []
			for param, value in params_copy.items():
				if get_input_type(url, param) == "hidden":
					deleted_params.append({param: value})
					del params_copy[param]
			if deleted_params:
				nohidden_response = make_auth_request(method, url, params_copy, COOKIE_HTTP_HEADER)
				if auth_response.content != nohidden_response.content:
					print("[!] CSRF could have been implemented as a hidden input value")
					print("[*] Removed hidden params:")
					pprint(deleted_params)

	# Command Injection
	# =================
	if CONFIG_TO_SCAN[RESULT_KEY_CMD]:
		print("\n[*] Scanning for command injection vulnerabilities")
		for method in params.keys():
			method_params = params[method]
			vulnerable = False
			for param in method_params.keys():
				params_copy = deepcopy(method_params)
				response = make_auth_request(method, url, method_params, COOKIE_HTTP_HEADER)
				initial_length = int(response.headers['content-length'])
				print("[*] Initial response content length: %d" % initial_length)

				# Scan for potential command injection vulns
				for x in commandExecList:
					params_copy[param] = x.strip()
					response = make_auth_request(method, url, params_copy, COOKIE_HTTP_HEADER)
					delta = int(response.headers['content-length']) - initial_length

					# Search for specific echo string 'gaw4f4sdaf12f', output of passwd or id command.
					if 'gaw4f4sdaf12f' in response.content or \
						'root:x:0:0' in response.content or \
						'/bin' in response.content or \
						'uid=' in response.content:
						print("[!] Module is potentially vulnerable to command injection!")
						print("[*] Payload used: %s" % params_copy)
						print("[*] Elasped Time: %d" % response.elapsed.total_seconds())
						print("[*] Response content length: %s" % response.headers['content-length'])
						add_result(RESULT_KEY_CMD, hostname, endpoint, params_copy, method)
						vulnerable = True
						break

					# sleep command is for 10 seconds
					elif response.elapsed.total_seconds() > 10:
						print("[*] Module is potentially vulnerable to blind command injection!")
						print("[*] Payload used: %s" % params_copy)
						print("[*] Elasped Time: %d" % response.elapsed.total_seconds())
						print("[*] Response content length: %s" % response.headers['content-length'])
						add_result(RESULT_KEY_CMD, hostname, endpoint, params_copy, method)
						vulnerable = True
						break

				if vulnerable:
					break

	# Server Side Injection
	# =====================
	# 1. LFI, RFI has the same capabilities, we include itself will cause the response to baloon
	#    We try the file name with or without .php extension, and 0 to 2 levels higher in the FS
	# 2. PHP code exec is hard to say exactly
	if CONFIG_TO_SCAN[RESULT_KEY_SSCI]:
		print("\n[*] Scanning for Server Side Command Injection vulnerabilities")
		for method in params.keys():
			method_params = params[method]
			vulnerable = False
			for param in method_params.keys():
				params_copy = deepcopy(method_params)
				response = make_auth_request(method, url, method_params, COOKIE_HTTP_HEADER)
				initial_length = len(response.content)
				print("[*] Initial response content length: %d" % initial_length)

				# Scan for LFI/RFI
				for probe in SSCI_PROBES:
					params_copy[param] = probe % filename.split('.')[0]
					response = make_auth_request(method, url, params_copy, COOKIE_HTTP_HEADER)
					if len(response.content) > 5 * initial_length:
						print("[!] Highly likely vulnerable to SSCI, massive response size due to self inclusion: %d" % len(response.content))
						add_result(RESULT_KEY_SSCI, hostname, endpoint, params_copy, method)
						vulnerable = True
						break

				if vulnerable:
					break

	# for method in params.keys():
	# 		method_params = params[method]
	# 		vulnerable = False
	# 	for param in method_params.keys():
	# 		params_copy = deepcopy(method_params)
	# 		response = make_auth_request(method, url, method_params, COOKIE_HTTP_HEADER)
	# 		initial_length = int(response.headers['content-length'])
	# 		print("[*] Initial response content length: %d" % initial_length)

	# 		# Scan for potential vulnerabilities
	# 		for x in serverInjectList:
	# 			method_params[key] = x.replace("\n", "")
	# 			#response = make_request(method, url, method_params)
	# 			response = make_auth_request(method, url, method_params, COOKIE_HTTP_HEADER)
	# 			print "\n[*]Scanning for server side injection vulnerabilities..."
	# 		 	print "[*]Payload used: " + str(method_params)
	# 		 	print "[*]Elasped Time: " + str(response.elapsed.total_seconds())
	# 		 	print "[*]Response content length: " + str(response.headers['content-length'])
	# 			print "[*]Response content: \n" + response.content

	# 			delta = int(response.headers['content-length']) - int(initial_length)

	# 			#Searches for specific echo string vq3rio13dj8x, or output of passwd
	# 			if response.content.find("root:x:0:0") != -1 or response.content.find("/bin") != -1:
	# 				print "[*]Module potentially vulnerable to sever side injection!"
	# 				server_side_exploitable = "yes"
	# 				with open('results.txt', 'a') as result:
	# 					result.write(json.dumps({ "class":"Server Side Code Injection", "results":{ hostname:[ { "endpoint":endpoint, "params":method_params, "method": method }] }}) + '\n')
	# 				break

	# 			elif response.elapsed.total_seconds() > 12:
	# 				print "[*]Vulnerable to blind sever side injection"
	# 				server_side_exploitable = "yes"
	# 				with open('results.txt', 'a') as result:
	# 					result.write(json.dumps({ "class":"Server Side Code Injection", "results":{ hostname:[ { "endpoint":endpoint, "params":method_params, "method": method }] }}) + '\n')
	# 				break

	# Check for open redirects
	# ========================
	# 1. Parameter value is contained in redirected URL
	if CONFIG_TO_SCAN[RESULT_KEY_REDIR]:
		print("\n[*] Scanning for open redirect vulnerabilities")
		for method in params.keys():
			method_params = params[method]
			response = make_request(method, url, method_params)
			request_url = response.request.url
			for history_response in response.history:
				if 300 <= history_response.status_code < 400:
					print("[!] Request history contains redirect: %s (%d)" % (history_response.url, history_response.status_code))
			for param, value in method_params.items():
				parsed_url = urlparse(response.url)
				if parsed_url.path.endswith(str(value)):
					print("[!] Redirected URL path ends with parameter value (%s=%s)" % (param, value))
					add_result(RESULT_KEY_REDIR, hostname, endpoint, method_params, method)

			if CONFIG_USE_FIREFOX:
				print("[*] Using Firefox to detect open redirects")
				options = Options()
				options.set_headless(headless=True)
				firefox = webdriver.Firefox(firefox_options=options)
				firefox.get(request_url)
				print("[*] Waiting for preconfigured time: %ds" % CONFIG_REDIR_WAIT)
				time.sleep(CONFIG_REDIR_WAIT)
				for param, value in method_params.items():
					if value in firefox.current_url:
						print("[!] Redirected URL path contains parameter value (%s=%s)" % (param, value))
						add_result(RESULT_KEY_REDIR, hostname, endpoint, method_params, method)
				firefox.quit()

	# Check for unsanitized inputs
	# ============================
	# 1. Using a few random values and checking if response changes
	#    We are looking for whether first delta changes (i.e. original input is a valid input)
	print("\n[*] Scanning for unsanitized inputs leading to SQLi or Directory Traversal vulnerabilities")
	for method in params.keys():
		method_params = params[method]
		response = make_request(method, url, method_params)
		prev_html = response.content
		first_delta = False
		for i in range(3):
			params_copy = deepcopy(method_params)
			for key in params_copy.keys():
				params_copy[key] = binascii.hexlify(os.urandom(20))
			request = Request(method, url, params=params_copy)
			prepared_request = session.prepare_request(request)
			response = session.send(prepared_request)
			delta = difflib.context_diff(prev_html, response.content)
			count = 0
			for line in delta:
				count += 1
			if i == 0 and count > 0:
				first_delta = True
			print("[*] Delta line count: %d" % count)
			prev_html = response.content

		if first_delta and CONFIG_TO_SCAN[RESULT_KEY_DIR]:
			print("[*] Non-zero first delta, trying directory traversal probes")
			vulnerable = False
			for param in method_params.keys():
				params_copy = deepcopy(method_params)
				for probe in DIR_TRAVERSAL_PROBES:
					params_copy[param] = probe
					response = make_request(method, url, params_copy)
					if "root:x:0:0" in response.content:
						print("[!] Found directory traversal indication using parameter value (%s=%s)" % (param, probe))
						add_result(RESULT_KEY_DIR, hostname, endpoint, params_copy, method)
						vulnerable = True
						break
				if vulnerable:
					break

		if CONFIG_TO_SCAN[RESULT_KEY_SQLI]:
			print("[*] Scanning for SQLi vulnerablities")
			for param in method_params.keys():
				params_copy = deepcopy(method_params)
				vulnerable = False
				for probe in SQLI_PROBES:
					params_copy[param] = probe
					response = make_request(method, url, params_copy)
					delta_lines = sum(1 for _ in difflib.context_diff(prev_html, response.content))
					if "SLEEP" in probe or "sleep" in probe:
						if response.elapsed.total_seconds() > CONFIG_SQLI_SLEEP_TIME:
							print("[!] Highly possible SQLi, probe triggered server sleep using parameter value (%s=%s)" % (param, probe))
							add_result(RESULT_KEY_SQLI, hostname, endpoint, params_copy, method)
							vulnerable = True
							break
					if delta_lines > 5:
						print("[!] Possible SQLi, probe triggered large response delta using parameter value (%s=%s)" % (param, probe))
						add_result(RESULT_KEY_SQLI, hostname, endpoint, params_copy, method)
						vulnerable = True
						break
				if vulnerable:
					break

def make_request(method, url, params, headers={}):
	if method == 'POST':
		return session.post(url, data=params, headers=headers)
	elif method == 'GET':
		return session.get(url, params=params, headers=headers)
	else:
		raise ValueError("Unknown method %s" % method)


def make_auth_request(method, url, params, cookie):
	if method == 'POST':
		return session.post(url, data=params, headers=cookie)
	elif method == 'GET':
		return session.get(url, params=params, headers=cookie)
	else:
		raise ValueError("Unknown method %s" % method)

def get_input_type(url, name):
	with open('logs/form_data.json', 'r') as file:
		form_data = json.loads(file.read())
		for form in form_data:
			if form['_url'] == url:
				for field in form['_fields']:
					field_name = field.get('name')
					if field_name == name:
						return field.get('type')
		return None

def add_result(result_key, hostname, endpoint, params, method):
	if not hostname in RESULTS[result_key]['results'].keys():
		RESULTS[result_key]['results'][hostname] = []
	RESULTS[result_key]['results'][hostname].append({
		'endpoint': endpoint,
		'params': params,
		'method': method
	})

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage: %s <JSON File>" % sys.argv[0])
	else:
		with open(sys.argv[1], 'r') as file:
			scan_data_list = json.loads(file.read())
			for scan_data in scan_data_list:
				scan_config = scan_data.get('scan_config') or {}
				print(scan_config)
				for result_key in scan_config.keys():
					if result_key in CONFIG_TO_SCAN.keys():
						CONFIG_TO_SCAN[result_key] = scan_config[result_key]
				scan(scan_data['url'], scan_data['params'])

		print('\nScan Results')
		print('============')
		pprint(RESULTS)

		with open('logs/scan_results.json', 'w') as file:
			file.write(json.dumps(RESULTS, indent=2, separators=(',', ': ')))
