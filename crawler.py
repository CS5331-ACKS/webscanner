import requests
import re
from pprint import pprint
from bs4 import BeautifulSoup

REGEX_HTML = re.compile('(text\/html|application\/xhtml\+xml).*')
REGEX_HOST = re.compile('http(|s):\/\/.+?\/')

def run():
  url = 'https://github.com/CS5331-ACKS/webscanner/'
  urls = visit(url)
  pprint(urls)

'''
url: string representing a URL

if host responds with a HTML document, returns a list of processed URLs in the document
else returns None
'''
def visit(url):
  # Initiate connection, defer downloading of response body
  try:
    r = requests.get(url, stream=True)
  except requests.exceptions.RequestException as e:
    print('Connection error')
    return None

  # Check if content-type is html
  if REGEX_HTML.match(r.headers['content-type']) is None:
    print('Content-type is not html')
    r.close()
    return None

  # Extract domain from host url
  matches = REGEX_HOST.match(r.url)
  if matches is None:
    print('Host is not http or https')
    r.close()
    return None

  # Get response content
  domain = matches.group(0)
  html = r.text
  r.close()

  # Parse HTML and look for <a> tags
  soup = BeautifulSoup(html, 'html.parser')
  urls = []

  for a in soup.find_all('a'):
    link = a.get('href')

    if link is None:
      continue
    elif link.startswith('/'):
      urls.append(domain + link[1:])
    elif link.lower().startswith('http://') or link.lower().startswith('https://'):
      urls.append(link)

  return urls

if __name__ == '__main__':
  run()
