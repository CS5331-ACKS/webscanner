import requests
import re
import json
from Queue import Queue
from urlparse import urlparse, urljoin
from pprint import pprint
from bs4 import BeautifulSoup

REGEX_HTML = re.compile('(text\/html|application\/xhtml\+xml).*')
STARTING_URL = u'http://192.168.56.101/'
VISITED_URLS_FILE = 'visited_urls.json'
PROCESSED_FORMS_FILE = 'form_data.json'

queue = Queue()
visited_urls = set()
hostname = ''
processed_forms = []

def run():
  global hostname

  # Seed the queue
  queue.put(STARTING_URL)

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
    urls, forms = results

    # Enqueue discovered URLs
    for u in urls:
      queue.put(u)

    # Store results
    processed_forms.extend(forms)

  # Write visited_urls and processed_forms into separate JSON files
  pprint(visited_urls)
  pprint(processed_forms)
  with open(VISITED_URLS_FILE, 'w') as outfile:
    json.dump(list(visited_urls), outfile, indent=2, separators=(',', ': '), sort_keys=True)
    outfile.write("\n")
  with open(PROCESSED_FORMS_FILE, 'w') as outfile:
    json.dump(processed_forms, outfile, indent=2, separators=(',', ': '), sort_keys=True)
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
      r = requests.post(url, data=params, stream=True)
    elif method == 'GET':
      r = requests.get(url, params=params, stream=True)
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
    print('Host is not http or https: ' + r.url)
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

  # Process <form> tags and their children <input> tags
  forms = []
  for form in soup.find_all('form'):
    form_data = form.attrs
    form_data[u'_fields'] = map(lambda input: input.attrs, form.find_all('input'))
    form_data[u'_url'] = r.url
    forms.append(form_data)

  return (urls, forms)

if __name__ == '__main__':
  run()
