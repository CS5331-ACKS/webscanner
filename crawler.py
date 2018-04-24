import requests
import re
import json
import sys
from Queue import Queue
from urlparse import urlparse, urljoin, parse_qs
from pprint import pprint
from bs4 import BeautifulSoup

REGEX_HTML = re.compile('(text\/html|application\/xhtml\+xml).*')
VISITED_URLS_FILE = 'logs/visited_urls.json'
PROCESSED_FORMS_FILE = 'logs/form_data.json'
SCAN_DATA_FILE = 'logs/scan_data.json'

cookie_data = open('test.txt', 'r').read()
COOKIE = {'Cookie': cookie_data}

queue = Queue()
visited_urls = set()
hostname = ''
processed_forms = []
scan_data_list = []

def run(starting_url):
	global hostname

	# Seed the queue
	queue.put(starting_url)

	while not queue.empty():
		url = queue.get()

		# Check if URL has already been visited
		if url in visited_urls:
			print('URL already visited: ' + url)
			continue

		# Check if URL is bounded within the provided hostname
		host = urlparse(url)
		current_hostname = host.scheme + '://' + host.netloc
		if not hostname:
			hostname = current_hostname
		elif hostname != current_hostname:
			print('URL outside of domain scope: ' + url)
			continue

		# Visit the URL
		results = visit(url)
		visited_urls.add(url)
		if results is None:
			continue
		urls, forms, scan_data = results

		# Enqueue discovered URLs
		for u in urls:
			queue.put(u)

		# Store results
		processed_forms.extend(forms)
		scan_data_list.extend(scan_data)

	# Write visited_urls and processed_forms into separate JSON files
	print("\nVisited URLS")
	print("============")
	pprint(visited_urls)
	print("\nProcessed Forms")
	print("=================")
	pprint(processed_forms)
	print("\nScan Data")
	print("===========")
	pprint(scan_data_list)
	with open(VISITED_URLS_FILE, 'w') as outfile:
		json.dump(list(visited_urls), outfile, indent=2, separators=(',', ': '), sort_keys=True)
		outfile.write("\n")
	with open(PROCESSED_FORMS_FILE, 'w') as outfile:
		json.dump(processed_forms, outfile, indent=2, separators=(',', ': '), sort_keys=True)
		outfile.write("\n")
	with open(SCAN_DATA_FILE, 'w') as outfile:
		json.dump(scan_data_list, outfile, indent=2, separators=(',', ': '), sort_keys=True)
		outfile.write("\n")

'''
url: string representing a URL

if host responds with a HTML document:
  returns a tuple containing (set of processed URLs, list of form dicts)
else:
  returns None
'''
def visit(url, method='GET', params={}):
	# Initiate connection, defer downloading of response body
	try:
		if method == 'POST':
			r = requests.post(url, data=params, stream=True, headers=COOKIE)
		elif method == 'GET':
			r = requests.get(url, params=params, stream=True, headers=COOKIE)
		else:
			print('Invalid HTTP method')
			return None
	except requests.exceptions.RequestException as e:
		print('Connection error: ' + url)
		return None

	# Detect redirects
	if url != r.url:
		visited_urls.add(r.url)

	# Check if content-type is html
	if REGEX_HTML.match(r.headers['content-type']) is None:
		print('Content-type is not html: ' + r.url)
		r.close()
		return None

	# Parse from host url
	host = urlparse(r.url)
	if host.scheme != 'http' and host.scheme != 'https':
		print('Scheme is not http or https: ' + r.url)
		r.close()
		return None

	# Get response content
	html = r.text
	r.close()

	# Parse HTML
	soup = BeautifulSoup(html, 'html.parser')

	# Process <a> tags
	urls = set()
	for a in soup.find_all('a'):
		link = a.get('href')
		if link is None:
	  		continue

		link = urlparse(link)
		if link.netloc:
			# don't change the link, unless the scheme is missing
			if not link.scheme:
				link = link._replace(scheme = host.scheme)
				urls.add(link.geturl())
		else:
			# link is a relative url
			urls.add(urljoin(host.geturl(), link.geturl()))

	# Extract GET parameters if applicable
	scan_data = []
	parsed_url = urlparse(url)
	if parsed_url.query:
		get_params = parse_qs(parsed_url.query)
		# We assume that GET parameters are only set once, i.e. no repeats and
		# not teated as an array by the browser
		get_params = {key:value[0] for key, value in get_params.items()}
		scan_data.append({'url': url.split("?")[0], 'params': {"GET": get_params}})

	# Process <form> tags and their children <input> tags
	forms = []
	for form in soup.find_all('form'):
		form_data = form.attrs
		form_data[u'_fields'] = map(lambda input: input.attrs, form.find_all('input'))
		form_data[u'_url'] = r.url
		forms.append(form_data)

		# Extract form parameters with respect to method
		form_method = form.get('method') or ""
		if form_method.upper() in ["GET", "POST"]:
			form_action = form.get('action') or ""
			form_action_url = urljoin(url, form_action)
			form_params = {input.get('name'): input.get('value') for input in form.find_all('input') if input.get('name')}
			scan_data.append({'url': url, 'params': {form_method: form_params}})

	return (urls, forms, scan_data)

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage: %s <URL>" % sys.argv[0])
	else:
		run(sys.argv[1])
