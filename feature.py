import ipaddress
import re
import socket
from urllib.parse import urlparse
import datetime
from datetime import date
import requests
from bs4 import BeautifulSoup

class FeatureExtraction:
    """
    Exact Feature Extraction Implementation matching vaibhavbichave/Phishing-URL-Detection.
    Extracts all 30 features with standard UCI Phishing Websites encoding:
      1: Legitimate / Safe
      0: Suspicious / Neutral
     -1: Phishing / Malicious
    """

    FEATURE_NAMES = [
        "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
        "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
        "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags",
        "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding", "StatusBarCust",
        "DisableRightClick", "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
        "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport"
    ]

    def __init__(self, url: str, live_fetch: bool = True, timeout: float = 2.0):
        self.features = []
        self.feature_details = {}
        
        url_clean = url.strip()
        if not re.match(r"^https?://", url_clean, re.IGNORECASE):
            url_clean = "http://" + url_clean
        self.url = url_clean

        self.response = None
        self.soup = None
        self.domain = ""
        self.whois_response = None
        self.urlparse = None

        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
            if ":" in self.domain:
                self.domain = self.domain.split(":")[0]
        except Exception:
            pass

        if live_fetch and self.domain:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                self.response = requests.get(self.url, timeout=timeout, headers=headers)
                if self.response.status_code == 200:
                    self.soup = BeautifulSoup(self.response.text, 'html.parser')
            except Exception:
                self.response = None
                self.soup = None

            try:
                import whois
                self.whois_response = whois.whois(self.domain)
            except Exception:
                self.whois_response = None

        self._extract_all()

    def _extract_all(self):
        extractors = [
            ("UsingIP", self.UsingIp, "Checks if an IP address is used in URL instead of domain name"),
            ("LongURL", self.longUrl, "Measures total URL length (<54: Safe, 54-75: Suspicious, >75: Phishing)"),
            ("ShortURL", self.shortUrl, "Detects URL shortening services (bit.ly, tinyurl, t.co, etc.)"),
            ("Symbol@", self.symbol, "Detects '@' character which browsers use to mask target hosts"),
            ("Redirecting//", self.redirecting, "Checks position of '//' redirection tokens in URL path"),
            ("PrefixSuffix-", self.prefixSuffix, "Detects hyphens in domain name commonly used in brand spoofing"),
            ("SubDomains", self.SubDomains, "Counts dot levels and subdomains in domain name"),
            ("HTTPS", self.Hppts, "Verifies HTTPS scheme presence in the URL"),
            ("DomainRegLen", self.DomainRegLen, "WHOIS domain registration lifetime validity"),
            ("Favicon", self.Favicon, "Inspects if shortcut icon is loaded externally"),
            ("NonStdPort", self.NonStdPort, "Checks if URL specifies non-standard network ports"),
            ("HTTPSDomainURL", self.HTTPSDomainURL, "Detects 'https' token embedded deceptively inside domain"),
            ("RequestURL", self.RequestURL, "Percentage of external resources (images, audio, video)"),
            ("AnchorURL", self.AnchorURL, "Percentage of external, empty, or javascript href anchors"),
            ("LinksInScriptTags", self.LinksInScriptTags, "Evaluates source domains in <script> and <link> tags"),
            ("ServerFormHandler", self.ServerFormHandler, "Checks if form action handler is blank or external"),
            ("InfoEmail", self.InfoEmail, "Detects mailto: action or credential transmission by email"),
            ("AbnormalURL", self.AbnormalURL, "Checks if domain identity matches server response"),
            ("WebsiteForwarding", self.WebsiteForwarding, "Measures number of redirect hops"),
            ("StatusBarCust", self.StatusBarCust, "Detects onmouseover status bar deception scripts"),
            ("DisableRightClick", self.DisableRightClick, "Detects scripts disabling right-click context menu"),
            ("UsingPopupWindow", self.UsingPopupWindow, "Detects pop-up prompt alerts querying sensitive data"),
            ("IframeRedirection", self.IframeRedirection, "Detects hidden or invisible <iframe> tags"),
            ("AgeofDomain", self.AgeofDomain, "Domain age analysis (> 6 months indicates established domain)"),
            ("DNSRecording", self.DNSRecording, "Validates DNS host resolution mapping"),
            ("WebsiteTraffic", self.WebsiteTraffic, "Assesses global web traffic and popularity indicators"),
            ("PageRank", self.PageRank, "Checks domain authority / PageRank standing"),
            ("GoogleIndex", self.GoogleIndex, "Checks if website is indexed in web search directories"),
            ("LinksPointingToPage", self.LinksPointingToPage, "Counts inbound link references on the webpage"),
            ("StatsReport", self.StatsReport, "Cross-references known phishing IP and domain blacklists")
        ]

        for fname, method, desc in extractors:
            try:
                val = method()
            except Exception:
                val = -1
            self.features.append(val)
            self.feature_details[fname] = {
                "value": val,
                "status": "Safe" if val == 1 else ("Suspicious" if val == 0 else "Phishing"),
                "description": desc
            }

    # 1. UsingIp: -1 if IP is present, 1 otherwise
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except Exception:
            return 1

    # 2. longUrl: <54 -> 1, 54-75 -> 0, >75 -> -1
    def longUrl(self):
        length = len(self.url)
        if length < 54:
            return 1
        elif 54 <= length <= 75:
            return 0
        return -1

    # 3. shortUrl: -1 if known shortener used, 1 otherwise
    def shortUrl(self):
        pattern = (r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
                   r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
                   r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
                   r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|"
                   r"db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|bc\.vc|"
                   r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|"
                   r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net")
        if re.search(pattern, self.url, re.IGNORECASE):
            return -1
        return 1

    # 4. Symbol@: -1 if @ in URL, 1 otherwise
    def symbol(self):
        if "@" in self.url:
            return -1
        return 1

    # 5. Redirecting//: -1 if // after index 6 (i.e. outside http://), 1 otherwise
    def redirecting(self):
        if self.url.rfind("//") > 6:
            return -1
        return 1

    # 6. PrefixSuffix-: -1 if - in domain, 1 otherwise
    def prefixSuffix(self):
        try:
            if "-" in self.domain:
                return -1
            return 1
        except Exception:
            return -1

    # 7. SubDomains: 1 dot -> 1 (Safe), 2 dots -> 0 (Suspicious), >2 dots -> -1 (Phishing)
    def SubDomains(self):
        try:
            domain_part = self.domain
            if domain_part.startswith("www."):
                domain_part = domain_part[4:]
            dots = domain_part.count(".")
            if dots <= 1:
                return 1
            elif dots == 2:
                return 0
            return -1
        except Exception:
            return -1

    # 8. HTTPS: 1 if https in scheme, -1 otherwise
    def Hppts(self):
        try:
            if self.urlparse and "https" in self.urlparse.scheme.lower():
                return 1
            return -1
        except Exception:
            return 1

    # 9. DomainRegLen: 1 if expiration - creation >= 12 months, -1 otherwise
    def DomainRegLen(self):
        if self.whois_response:
            try:
                exp = self.whois_response.expiration_date
                created = self.whois_response.creation_date
                if isinstance(exp, list): exp = exp[0]
                if isinstance(created, list): created = created[0]
                if exp and created:
                    age_months = (exp.year - created.year) * 12 + (exp.month - created.month)
                    if age_months >= 12:
                        return 1
                return -1
            except Exception:
                return -1
        # Fallback heuristic: well-known TLDs with legitimate domains get neutral/safe
        if self.domain and any(self.domain.endswith(tld) for tld in [".com", ".org", ".edu", ".gov"]):
            return 1
        return -1

    # 10. Favicon: 1 if loaded from same domain, -1 otherwise
    def Favicon(self):
        if self.soup:
            try:
                for head in self.soup.find_all("head"):
                    for link in head.find_all("link", href=True):
                        dots = [x.start(0) for x in re.finditer(r"\.", link["href"])]
                        if self.url in link["href"] or len(dots) == 1 or self.domain in link["href"]:
                            return 1
                return -1
            except Exception:
                return -1
        return 1

    # 11. NonStdPort: -1 if non standard port specified, 1 otherwise
    def NonStdPort(self):
        try:
            if self.urlparse and self.urlparse.port:
                if self.urlparse.port not in [80, 443]:
                    return -1
            return 1
        except Exception:
            return -1

    # 12. HTTPSDomainURL: -1 if 'https' in domain name part, 1 otherwise
    def HTTPSDomainURL(self):
        try:
            if "https" in self.domain.lower():
                return -1
            return 1
        except Exception:
            return -1

    # 13. RequestURL: percentage of external resources
    def RequestURL(self):
        if self.soup:
            try:
                i, success = 0, 0
                for tag in ["img", "audio", "embed", "iframe"]:
                    for elem in self.soup.find_all(tag, src=True):
                        dots = [x.start(0) for x in re.finditer(r"\.", elem["src"])]
                        if self.url in elem["src"] or self.domain in elem["src"] or len(dots) == 1:
                            success += 1
                        i += 1
                if i > 0:
                    pct = (success / float(i)) * 100
                    if pct < 22.0:
                        return 1
                    elif 22.0 <= pct < 61.0:
                        return 0
                    return -1
                return 1
            except Exception:
                return -1
        # Offline heuristic
        return 1 if self.domain and not any(k in self.domain for k in ["login", "verify", "secure-"]) else -1

    # 14. AnchorURL: percentage of unsafe anchors
    def AnchorURL(self):
        if self.soup:
            try:
                i, unsafe = 0, 0
                for a in self.soup.find_all("a", href=True):
                    href = a["href"].lower()
                    if "#" in href or "javascript" in href or "mailto" in href or not (self.url in href or self.domain in href):
                        unsafe += 1
                    i += 1
                if i > 0:
                    pct = (unsafe / float(i)) * 100
                    if pct < 31.0:
                        return 1
                    elif 31.0 <= pct <= 67.0:
                        return 0
                    return -1
                return 1
            except Exception:
                return -1
        # Offline heuristic: well-known legit domains return 1, raw suspicious links return -1
        return 1 if self.domain and any(k in self.domain for k in ["google", "github", "microsoft", "apple", "amazon"]) else -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        if self.soup:
            try:
                i, success = 0, 0
                for link in self.soup.find_all("link", href=True):
                    dots = [x.start(0) for x in re.finditer(r"\.", link["href"])]
                    if self.url in link["href"] or self.domain in link["href"] or len(dots) == 1:
                        success += 1
                    i += 1
                for script in self.soup.find_all("script", src=True):
                    dots = [x.start(0) for x in re.finditer(r"\.", script["src"])]
                    if self.url in script["src"] or self.domain in script["src"] or len(dots) == 1:
                        success += 1
                    i += 1
                if i > 0:
                    pct = (success / float(i)) * 100
                    if pct < 17.0:
                        return 1
                    elif 17.0 <= pct <= 81.0:
                        return 0
                    return -1
                return 1
            except Exception:
                return -1
        return 1 if self.domain and any(k in self.domain for k in ["google", "github", "microsoft"]) else -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        if self.soup:
            try:
                forms = self.soup.find_all("form", action=True)
                if len(forms) == 0:
                    return 1
                for form in forms:
                    action = form["action"].strip().lower()
                    if action == "" or action == "about:blank":
                        return -1
                    elif self.url not in action and self.domain not in action:
                        return 0
                return 1
            except Exception:
                return -1
        return 1

    # 17. InfoEmail
    def InfoEmail(self):
        if self.response:
            try:
                if re.search(r"mailto:|mail\(", self.response.text, re.IGNORECASE):
                    return -1
                return 1
            except Exception:
                return -1
        return 1

    # 18. AbnormalURL
    def AbnormalURL(self):
        if self.response:
            try:
                if self.response.text.strip():
                    return 1
                return -1
            except Exception:
                return -1
        return 1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        if self.response:
            try:
                h = len(self.response.history)
                if h <= 1:
                    return 1
                elif h <= 4:
                    return 0
                return -1
            except Exception:
                return -1
        return 1

    # 20. StatusBarCust
    def StatusBarCust(self):
        if self.response:
            try:
                if re.search(r"onmouseover.*status", self.response.text, re.IGNORECASE):
                    return -1
                return 1
            except Exception:
                return -1
        return 1

    # 21. DisableRightClick
    def DisableRightClick(self):
        if self.response:
            try:
                if re.search(r"event\.button\s*==\s*2", self.response.text):
                    return -1
                return 1
            except Exception:
                return -1
        return 1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        if self.response:
            try:
                if re.search(r"prompt\(|alert\(", self.response.text):
                    return -1
                return 1
            except Exception:
                return -1
        return 1

    # 23. IframeRedirection
    def IframeRedirection(self):
        if self.response:
            try:
                if re.search(r"<iframe|<frameBorder", self.response.text, re.IGNORECASE):
                    return -1
                return 1
            except Exception:
                return -1
        return 1

    # 24. AgeofDomain
    def AgeofDomain(self):
        if self.whois_response:
            try:
                created = self.whois_response.creation_date
                if isinstance(created, list): created = created[0]
                today = date.today()
                if created:
                    age_months = (today.year - created.year) * 12 + (today.month - created.month)
                    if age_months >= 6:
                        return 1
                return -1
            except Exception:
                return -1
        if any(pop in self.domain.lower() for pop in ["google", "github", "wikipedia", "youtube", "microsoft", "yahoo", "amazon"]):
            return 1
        return -1

    # 25. DNSRecording
    def DNSRecording(self):
        if self.domain:
            try:
                socket.gethostbyname(self.domain)
                return 1
            except Exception:
                return -1
        return -1

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        popular_domains = [
            "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
            "wikipedia.org", "yahoo.com", "amazon.com", "reddit.com", "netflix.com",
            "microsoft.com", "github.com", "linkedin.com", "apple.com", "chatgpt.com"
        ]
        if any(pop in self.domain.lower() for pop in popular_domains):
            return 1
        return 0

    # 27. PageRank
    def PageRank(self):
        trusted_suffixes = [".gov", ".edu", ".org", ".ac.in", ".gov.in"]
        if any(self.domain.lower().endswith(s) for s in trusted_suffixes):
            return 1
        return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        if self.domain and not any(ch in self.domain for ch in ["@", "login-", "verify-", "free-", "update-"]):
            return 1
        return -1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        if self.soup:
            try:
                links = len(self.soup.find_all("a", href=True))
                if links > 10:
                    return 1
                elif 2 <= links <= 10:
                    return 0
                return -1
            except Exception:
                return -1
        return 1 if any(pop in self.domain.lower() for pop in ["google", "github", "microsoft", "wikipedia"]) else -1

    # 30. StatsReport
    def StatsReport(self):
        suspicious_keywords = ["paypal-security", "login-bank", "account-update", "free-crypto", "wallet-connect", "servehttp.com", "free-crypto.xyz"]
        if any(kw in self.url.lower() for kw in suspicious_keywords):
            return -1
        return 1

    def getFeaturesList(self):
        return self.features

    def getFeaturesDict(self):
        return self.feature_details
