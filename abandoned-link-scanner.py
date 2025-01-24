# Abandoned Link Scanner
# Copyright 2016-2025, Blaze Information Security
# https://www.blazeinfosec.com

from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.net import URL, UnknownHostException
from javax.net.ssl import SSLHandshakeException
from java.util import ArrayList, List
from java.util.concurrent import ConcurrentHashMap
import re
import socket
from threading import Lock

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Abandoned Link Scanner")
        
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        self.domain_cache = ConcurrentHashMap()
        self.MAX_CACHE_SIZE = 10000
        
        # Regular expressions for extracting URLs from HTML
        self.patterns = {
            'iframe': re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']'),
            'script': re.compile(r'<script[^>]+src=["\']([^"\']+)["\']'),
            'link': re.compile(r'<link[^>]+href=["\']([^"\']+)["\']'),
            'anchor': re.compile(r'<a[^>]+href=["\']([^"\']+)["\']'),
            'img': re.compile(r'<img[^>]+src=["\']([^"\']+)["\']'),
            'audio': re.compile(r'<audio[^>]+src=["\']([^"\']+)["\']'),
            'video': re.compile(r'<video[^>]+src=["\']([^"\']+)["\']'),
            'object': re.compile(r'<object[^>]+data=["\']([^"\']+)["\']'),
            'source': re.compile(r'<source[^>]+src=["\']([^"\']+)["\']'),
            'mailto': re.compile(r'mailto:([^"\'\s<>]+)')
        }
        
        self.ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        
        # Cloud service takeover patterns
        self.cloud_errors = {
            # NXDOMAIN checks
            'AWS_ELASTIC_BEANSTALK': ['NXDOMAIN', 'elasticbeanstalk.com'],
            'DISCOURSE': ['NXDOMAIN', 'trydiscourse.com'],
            'MICROSOFT_AZURE': ['NXDOMAIN', 'cloudapp.net', 'cloudapp.azure.com', 'azurewebsites.net', 'blob.core.windows.net', 'azure-api.net', 'azurehdinsight.net', 'azureedge.net', 'azurecontainer.io', 'database.windows.net', 'azuredatalakestore.net', 'search.windows.net', 'azurecr.io', 'redis.cache.windows.net', 'servicebus.windows.net', 'visualstudio.com'],

            # Status code checks
            'HELPRACE': ['HTTP_STATUS=301', 'helprace.com'],
            'LAUNCHROCK': ['HTTP_STATUS=500', 'launchrock.com'],

            # Content pattern checks
            'AWS_S3': ['The specified bucket does not exist', 's3.amazonaws.com'],
            'AGILE_CRM': ['Sorry, this page is no longer available.', 'agilecrm.com'],
            'AIREE': ['Error 402. Airee.ru Service Not Paid', 'airee.ru'],
            'ANIMA': ['The page you were looking for does not exist.', 'animaapp.io'],
            'BITBUCKET': ['Repository not found', 'bitbucket.io'],
            'CAMPAIGN_MONITOR': ['Trying to access your account?'],
            'CANNY': ['Company Not Found', 'There is no such company. Did you enter the right URL?'],
            'DIGITAL_OCEAN': ['Domain uses DO name servers with no records in DO.'],
            'GEMFURY': ['404: This page could not be found.', 'furyns.com'],
            'GETRESPONSE': ['With GetResponse Landing Pages, lead generation has never been easier'],
            'GHOST': ['Site unavailable\\.&#124;Failed to resolve DNS path for this host', 'ghost.io'],
            'HATENABLOG': ['404 Blog is not found', 'hatenablog.com'],
            'HELPJUICE': ['We could not find what you\'re looking for.', 'helpjuice.com'],
            'HELPSCOUT': ['No settings were found for this company:', 'helpscoutdocs.com'],
            'JETBRAINS': ['is not a registered InCloud YouTrack', 'youtrack.cloud'],
            'NGROK': ['ERR_NGROK_3200', 'ngrok.io'],
            'PANTHEON': ['404 error unknown site!'],
            'PINGDOM': ['Sorry, couldn\'t find the status page'],
            'README_IO': ['The creators of this project are still working on making everything perfect!', 'readme.io'],
            'READTHEDOCS': ['The link you have followed or the URL that you entered does not exist.'],
            'SHORT_IO': ['Link does not exist'],
            'SMARTJOBBOARD': ['This job board website is either expired or its domain name is invalid.', '52.16.160.97'],
            'SMUGMUG': [''],
            'STRIKINGLY': ['PAGE NOT FOUND.', 's.strikinglydns.com'],
            'SURGE_SH': ['project not found', 'na-west1.surge.sh'],
            'SURVEYSPARROW': ['Account not found.', 'surveysparrow.com'],
            'UBERFLIP': ['The URL you\'ve accessed does not provide a hub.', 'read.uberflip.com'],
            'UPTIMEROBOT': ['page not found', 'stats.uptimerobot.com'],
            'WORDPRESS': ['Do you want to register .*.wordpress.com?', 'wordpress.com'],
            'WORKSITES': ['Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.', 'worksites.net']
        }
        
        callbacks.registerScannerCheck(self)
        
        self.stdout.println("Abandoned Link Scanner loaded successfully!")
    
    def extract_domains(self, base_url, response):
        domains = set()
        
        response_info = self.helpers.analyzeResponse(response)
        if response_info.getInferredMimeType().lower() != "html":
            return domains
            
        html = self.helpers.bytesToString(response)
        
        for element, pattern in self.patterns.items():
            matches = pattern.finditer(html)
            for match in matches:
                try:
                    url_str = match.group(1)
                    if not url_str or len(url_str) > 2000:
                        continue
                            
                    # Special handling for mailto links
                    if element == 'mailto':
                        email_domain = url_str.split('@')[-1].strip()
                        if email_domain and not self.ip_pattern.match(email_domain):
                            domains.add(email_domain)
                        continue
                            
                    if url_str.startswith('//'):
                        url_str = 'http:' + url_str
                    elif not url_str.startswith(('http://', 'https://')):
                        if url_str.startswith('/'):
                            url_str = base_url.getProtocol() + '://' + base_url.getHost() + url_str
                        else:
                            continue
                        
                    url = URL(url_str)
                    domain = url.getHost()
                        
                    if not domain or self.ip_pattern.match(domain):
                        continue
                            
                    domains.add(domain)
                        
                except Exception as e:
                    self.stderr.println("Error processing URL {}: {}".format(url_str, str(e)))
                    continue
                        
        return domains
    
    def check_domain(self, domain):
        """Check if a domain is vulnerable to takeover."""
        if self.domain_cache.containsKey(domain):
            return self.domain_cache.get(domain), None
            
        response_str = None
        cname_records = []
        is_nxdomain = False

        # Check for direct S3 bucket first
        if domain.endswith('s3.amazonaws.com'):
            try:
                url = URL("https://" + domain)
                request_bytes = self.helpers.stringToBytes(
                    "GET / HTTP/1.1\r\nHost: " + domain + 
                    "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                
                response = self.callbacks.makeHttpRequest(url.getHost(), 443, True, request_bytes)
                if response:
                    response_str = self.helpers.bytesToString(response)
                    if 'NoSuchBucket' in response_str or 'The specified bucket does not exist' in response_str:
                        start_idx = response_str.find('The specified bucket does not exist')
                        if start_idx == -1:
                            start_idx = response_str.find('NoSuchBucket')
                        end_idx = start_idx + len('The specified bucket does not exist')
                        result = "Potential AWS_S3 takeover vulnerability"
                        self.domain_cache.put(domain, result)
                        return result, [[start_idx, end_idx]]
            except Exception as e:
                self.stderr.println("S3 check error for domain {}: {}".format(domain, str(e)))
        
        # Get CNAME records if not already collected
        if not cname_records:
            try:
                answers = socket.getaddrinfo(domain, None)
                for answer in answers:
                    if answer[4][0] not in cname_records:
                        cname_records.append(answer[4][0])
            except socket.gaierror:
                is_nxdomain = True
                # For NXDOMAIN, we'll highlight the entire response
                return "Domain NXDOMAIN - potential hijacking. Manual verification required to check if takeover is possible.", [[0, -1]]
            except Exception as e:
                self.stderr.println("DNS error for domain {}: {}".format(domain, str(e)))

        # Check for common cloud platforms by CNAME
        for cname in cname_records:
            if 's3.amazonaws.com' in cname:
                return "Potential AWS_S3 takeover vulnerability (CNAME match)", [[0, -1]]
            elif 'blob.core.windows.net' in cname:
                return "Potential AZURE takeover vulnerability (CNAME match)", [[0, -1]]

        # Get HTTP response if domain resolves
        if not is_nxdomain:
            try:
                url = URL("https://" + domain)
                request_bytes = self.helpers.stringToBytes(
                    "GET / HTTP/1.1\r\nHost: " + domain + 
                    "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                
                response = self.callbacks.makeHttpRequest(url.getHost(), 443, True, request_bytes)
                if response:
                    response_info = self.helpers.analyzeResponse(response)
                    response_str = self.helpers.bytesToString(response)
                    
                    # Check content patterns with more descriptive messages
                    for service, patterns in self.cloud_errors.items():
                        for pattern in patterns:
                            if pattern and pattern in response_str:
                                start_idx = response_str.index(pattern)
                                end_idx = start_idx + len(pattern)
                                
                                # More descriptive messages based on service
                                messages = {
                                    'SURGE_SH': "Surge.sh subdomain takeover - Project not found on Surge hosting",
                                    'AWS_S3': "AWS S3 bucket takeover - Bucket does not exist",
                                    'MICROSOFT_AZURE': "Azure subdomain takeover - Resource not found on Azure",
                                    'GITHUB_PAGES': "GitHub Pages takeover - Page not found",
                                    'HEROKU': "Heroku app takeover - App not found",
                                    'PANTHEON': "Pantheon site takeover - Site not found",
                                    'GHOST': "Ghost CMS takeover - Site unavailable",
                                    'NGROK': "Ngrok endpoint takeover - Tunnel not found",
                                    'READTHEDOCS': "ReadTheDocs takeover - Documentation not found",
                                    'WORDPRESS': "WordPress subdomain takeover - Site not registered",
                                    'SMUGMUG': "SmugMug takeover - Page not found",
                                    'HELPSCOUT': "HelpScout Docs takeover - Company not found",
                                    'JETBRAINS': "JetBrains YouTrack takeover - Instance not registered",
                                    'UPTIMEROBOT': "UptimeRobot status page takeover - Page not found"
                                }
                                
                                result = messages.get(service, "Potential {} takeover vulnerability - {}".format(service, pattern))
                                self.domain_cache.put(domain, result)
                                return result, [[start_idx, end_idx]]
                    
            except Exception as e:
                self.stderr.println("HTTP error for domain {}: {}".format(domain, str(e)))
                return "Connection failed - potential for hijacking", None

        if self.domain_cache.size() > self.MAX_CACHE_SIZE:
            self.domain_cache.clear()
            
        return None, None
    
    def doPassiveScan(self, base_request_response):
        issues = ArrayList()
        
        response = base_request_response.getResponse()
        if response is None:
            return None
            
        analyzed_url = self.helpers.analyzeRequest(base_request_response).getUrl()
        
        if not self.is_in_scope(analyzed_url):
            return None
        
        domains = self.extract_domains(analyzed_url, response)
        self.stdout.println("Found {} domains to check".format(len(domains)))
        
        for domain in domains:
            self.stdout.println("Checking domain: {}".format(domain))
            result, highlight_positions = self.check_domain(domain)
            if result:
                # Create a request to the vulnerable domain
                vulnerable_url = URL("https://" + domain)
                request_bytes = self.helpers.stringToBytes(
                    "GET / HTTP/1.1\r\nHost: " + domain + 
                    "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                
                try:
                    vulnerable_response = self.callbacks.makeHttpRequest(vulnerable_url.getHost(), 443, True, request_bytes)
                    if vulnerable_response:
                        request_response = [self.callbacks.applyMarkers(
                            self._create_request_response(vulnerable_url, request_bytes, vulnerable_response),
                            None,  # No request highlights
                            highlight_positions  # Response highlights as list of lists
                        )]
                    else:
                        request_response = [base_request_response]
                except:
                    request_response = [base_request_response]

                issue = CustomScanIssue(
                    base_request_response.getHttpService(),
                    analyzed_url,
                    request_response,
                    "Potential Domain Takeover",
                    "Domain: {}\nIssue: {}".format(domain, result),
                    "Medium"
                )
                issues.add(issue)
                self.stdout.println("Found issue with domain {}: {}".format(domain, result))
        
        return issues if issues.size() > 0 else None

    def _create_request_response(self, url, request, response):
        return self.callbacks.getHelpers().buildHttpService(
            url.getHost(),
            url.getPort() if url.getPort() > -1 else url.getDefaultPort(),
            url.getProtocol() == "https"
        )
    
    def consolidateDuplicateIssues(self, existing_issue, new_issue):
        if (existing_issue.getIssueName() == new_issue.getIssueName() and
            existing_issue.getIssueDetail() == new_issue.getIssueDetail()):
            return -1
        return 0

    def is_in_scope(self, url):
        return self.callbacks.isInScope(url)


class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return "Certain"
    
    def getIssueBackground(self):
        return """<p>Subdomain takeover vulnerabilities occur when a subdomain's DNS record points to a service (like GitHub Pages, Heroku, or AWS) that is no longer in use. 
This typically happens when:</p>
<ul>
    <li>A service was deprovisioned without removing the DNS record</li>
    <li>A third-party service subscription expired or was cancelled</li>
    <li>A cloud resource was deleted without updating DNS</li>
    <li>Project migrations left behind old DNS records</li>
</ul>

<p>These vulnerabilities are dangerous because they allow attackers to take control of the subdomain by:</p>
<ul>
    <li>Registering the same service/resource name that was previously used</li>
    <li>Serving malicious content under your domain</li>
    <li>Potentially stealing cookies, credentials, or sensitive data</li>
    <li>Launching phishing attacks with added credibility</li>
</ul>

<p>Common vulnerable services include:</p>
<ul>
    <li>AWS S3 buckets and Elastic Beanstalk applications</li>
    <li>Azure web apps and storage accounts</li>
    <li>GitHub Pages</li>
    <li>Heroku apps</li>
    <li>Various third-party services using CNAMEs</li>
</ul>"""

    def getRemediationBackground(self):
        return """<p>To prevent subdomain takeover vulnerabilities, follow these best practices:</p>
<ul>
    <li>Maintain an inventory of all subdomains and their associated services</li>
    <li>Implement a deprovisioning checklist that includes DNS record cleanup</li>
    <li>Regularly audit DNS records against active services</li>
    <li>Use DNS monitoring tools to detect changes or misconfigurations</li>
</ul>

<p>When a vulnerable subdomain is identified:</p>

<p><b>Immediate Actions:</b></p>
<ul>
    <li>Remove or update the DNS record immediately</li>
    <li>If the service is still needed, reclaim the resource name before removing the DNS record</li>
    <li>Verify no other subdomains are pointing to the same service</li>
</ul>

<p><b>Long-term Remediation:</b></p>
<ul>
    <li>Implement automated DNS record validation</li>
    <li>Use infrastructure as code to manage DNS records</li>
    <li>Create service decommissioning procedures</li>
    <li>Consider using DNS security features like DNSSEC</li>
    <li>Monitor certificate transparency logs for unauthorized certificates</li>
</ul>

<p><b>Recommended Tools:</b></p>
<ul>
    <li>subfinder - For subdomain enumeration</li>
    <li>subjack - For automated takeover detection</li>
    <li>DNSWatch - For DNS monitoring</li>
    <li>Certificate Transparency monitoring</li>
</ul>

<p><b>References:</b></p>
<ul>
    <li>can-i-take-over-xyz - https://github.com/EdOverflow/can-i-take-over-xyz</li>
    <li>Subdomain Takeover: Going beyond CNAME - https://0xpatrik.com/subdomain-takeover-ns/</li>
    <li>A Guide to DNS Takeovers: The Misunderstood Cousin of Subdomain Takeovers - https://projectdiscovery.io/blog/guide-to-dns-takeovers</li>
    <li>dead-domain-discovery - https://github.com/lauritzh/dead-domain-discovery</li>
</ul>
"""
    
    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return None
    
    def getHttpMessages(self):
        return self._http_messages
    
    def getHttpService(self):
        return self._http_service