import requests
from pprint import pprint

def scan(url, params):
	print("\n[*] Scanning: %s" % url)
	print("[*] Known Params:")
	pprint(params)

	response = requests.get(url, params=params['GET'])

	# Check for open redirects
	# ========================
	# 1. Parameter value is contained in redirected URL
	for param, value in params['GET'].items():
		if response.url.endswith(value):
			print("[!] Redirected URL ends with parameter (%s=%s)" % (param, value))

if __name__ == '__main__':
	scan('http://192.168.56.101/openredirect/openredirect.php', {'GET': {'redirect': 'success.html'}})