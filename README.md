# Webscanner Architecture

Our webscanner is split into 3 components which are chained together: the crawler, scanner and exploiter.

# Crawler

The crawler uses Python requests library to retrieve URLs and the BeautifulSoup4 library to parse the HTML and extract links. We considered only anchor tags, form actions in our crawler. The crawler also determines the input parameters to each URL.

# Scanner

The scanner takes the URLs with input parameters and applies various signature based detection probes to each of the parameters. It also uses Python requests library to probe the URLs. In special cases, it will also use Firefox webdriver when JavaScript execution is required.

An example of our probes is './../../../etc/passwd'. If the URL endpoint were vulnerable to directory traversal or local file inclusion, we can detect that by the output containing the string 'root:x:0:0', assuming a Linux system.

# Exploiter

The exploiter takes the scanner output, i.e. the list of suspected vulnerable URLs, and tries to generate an automated exploit depending on the vulnerability class. It shares its payload pool with the scanner and builds upon the successful probes where necessary to successfully exploit vulnerable URL endpoints.
