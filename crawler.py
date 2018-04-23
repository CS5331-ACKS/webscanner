import requests
import re
from urlparse import urlparse, urljoin
from pprint import pprint
from bs4 import BeautifulSoup

REGEX_HTML = re.compile('(text\/html|application\/xhtml\+xml).*')

def run():
  url = 'https://github.com/CS5331-ACKS/webscanner/'
  url = 'https://jigsaw.w3.org/HTTP/300/302.html'
  url = 'http://192.168.56.101/'
  url = 'http://192.168.56.101/sqli/sqli.php'

  urls, forms = visit(url)
  pprint(urls)
  pprint(forms)

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
