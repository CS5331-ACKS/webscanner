import requests
import re
from Queue import Queue
from urlparse import urlparse, urljoin
from pprint import pprint
from bs4 import BeautifulSoup

REGEX_HTML = re.compile('(text\/html|application\/xhtml\+xml).*')
STARTING_URL = u'http://192.168.56.101/'

queue = Queue()
visited_urls = set()
hostname = ''

discovered_urls = set()
processed_forms = []

def run():
  global hostname

  # Seed the queue
  queue.put(STARTING_URL)
  discovered_urls.add(STARTING_URL)

  while not queue.empty():
    url = queue.get()

    # Check if URL has already been visited
    if url in visited_urls:
      continue

    # Check if URL is bounded within the provided hostname
    host = urlparse(url)
    current_hostname = host.scheme + '://' + host.netloc
    if not hostname:
      hostname = current_hostname
    elif hostname != current_hostname:
      continue

    # Visit the URL
    # TODO what if visit() returns None
    urls, forms = visit(url)
    visited_urls.add(url)

    # Enqueue discovered URLs
    for u in urls:
      queue.put(u)

    # Store results
    discovered_urls.update(urls)
    processed_forms.extend(forms)

  # TODO
  # dump discovered_urls and processed_forms into a JSON file
  pprint(discovered_urls)
  pprint(processed_forms)

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
    print('Connection error')
    return None

  # Check if content-type is html
  if REGEX_HTML.match(r.headers['content-type']) is None:
    print('Content-type is not html')
    r.close()
    return None

  # Parse from host url
  host = urlparse(r.url)
  if host.scheme != 'http' and host.scheme != 'https':
    print('Host is not http or https')
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
