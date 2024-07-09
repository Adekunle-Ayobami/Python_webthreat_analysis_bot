import requests
from bs4 import BeautifulSoup
import pandas as pd
import ssl
import socket
import dns.resolver
import builtwith
from textblob import TextBlob
import time
from urllib.parse import urljoin

def get_page_content(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    return None

def scrape_website(url):
    content = get_page_content(url)
    if content:
        soup = BeautifulSoup(content, 'html.parser')
        return soup
    return None

def check_outdated_software(soup):
    outdated = False
    for meta in soup.find_all('meta'):
        if 'generator' in meta.attrs:
            generator = meta.attrs['generator']
            if 'WordPress' in generator and '5.0' in generator:  # Example condition
                outdated = True
    return outdated

def check_unsecured_forms(soup):
    unsecured_forms = []
    for form in soup.find_all('form'):
        if form.get('action', '').startswith('http:'):
            unsecured_forms.append(form)
    return unsecured_forms

def check_ssl_certificate(url):
    hostname = url.split('://')[-1].split('/')[0]
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    try:
        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        return ssl_info
    except:
        return None

def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers
    security_headers = {
        'Content-Security-Policy': headers.get('Content-Security-Policy'),
        'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
        'X-Frame-Options': headers.get('X-Frame-Options'),
        'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
        'X-XSS-Protection': headers.get('X-XSS-Protection')
    }
    return security_headers

def check_sql_injection(soup, url):
    payloads = ["'", '"', '1=1', 'OR 1=1', 'admin" --']
    vulnerable = False
    for form in soup.find_all('form'):
        for payload in payloads:
            data = {input_tag.get('name'): payload for input_tag in form.find_all('input')}
            action = form.get('action')
            full_url = urljoin(url, action)
            response = requests.post(full_url, data=data)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                vulnerable = True
                break
    return vulnerable

def check_xss_vulnerability(soup, url):
    payloads = ["<script>alert('XSS')</script>", '<img src=x onerror=alert("XSS")>', '<svg onload=alert("XSS")>']
    vulnerable = False
    for form in soup.find_all('form'):
        for payload in payloads:
            data = {input_tag.get('name'): payload for input_tag in form.find_all('input')}
            action = form.get('action')
            full_url = urljoin(url, action)
            response = requests.post(full_url, data=data)
            if payload in response.text:
                vulnerable = True
                break
    return vulnerable

def check_external_links(soup, url):
    external_links = []
    for a_tag in soup.find_all('a', href=True):
        link = urljoin(url, a_tag['href'])
        if not link.startswith(url):
            external_links.append(link)
    return external_links

def check_js_libraries(soup):
    js_libraries = []
    for script in soup.find_all('script', src=True):
        js_libraries.append(script['src'])
    return js_libraries

def check_broken_links(soup, url):
    broken_links = []
    for a_tag in soup.find_all('a', href=True):
        link = urljoin(url, a_tag['href'])
        try:
            response = requests.get(link)
            if response.status_code != 200:
                broken_links.append((link, response.status_code))
        except requests.exceptions.RequestException as e:
            broken_links.append((link, str(e)))
    return broken_links

def check_performance(url):
    start_time = time.time()
    try:
        response = requests.get(url)
        load_time = time.time() - start_time
        performance = {
            'load_time': load_time,
            'status_code': response.status_code
        }
    except requests.exceptions.RequestException as e:
        performance = {
            'load_time': None,
            'status_code': str(e)
        }
    return performance

def check_seo(soup):
    seo_analysis = {
        'title': soup.title.string if soup.title else 'No title found',
        'meta_description': None,
        'headings': {f'h{i}': len(soup.find_all(f'h{i}')) for i in range(1, 7)},
        'alt_texts': len([img for img in soup.find_all('img') if img.get('alt')])
    }
    for meta in soup.find_all('meta'):
        if meta.get('name') == 'description':
            seo_analysis['meta_description'] = meta.get('content')
    return seo_analysis

def check_mobile_friendly(soup):
    viewport = soup.find('meta', attrs={'name': 'viewport'})
    return viewport is not None

def check_accessibility(soup):
    accessibility = {
        'alt_texts': len([img for img in soup.find_all('img') if img.get('alt')]),
        'aria_labels': len([element for element in soup.find_all(attrs={"aria-label": True})]),
        'missing_alt_texts': len([img for img in soup.find_all('img') if not img.get('alt')])
    }
    return accessibility

def get_dns_info(domain):
    dns_info = {}
    try:
        dns_info['A'] = [str(ip) for ip in dns.resolver.resolve(domain, 'A')]
        dns_info['MX'] = [str(mx) for mx in dns.resolver.resolve(domain, 'MX')]
        dns_info['NS'] = [str(ns) for ns in dns.resolver.resolve(domain, 'NS')]
    except Exception as e:
        dns_info['error'] = str(e)
    return dns_info

def detect_technologies(url):
    return builtwith.parse(url)

def analyze_content(soup):
    texts = soup.get_text()
    blob = TextBlob(texts)
    sentiment = blob.sentiment
    content_analysis = {
        'polarity': sentiment.polarity,
        'subjectivity': sentiment.subjectivity
    }
    return content_analysis

# def check_malware(url):
#     api_key = '39f0023bfe58afb343c8cd3a63f1dcf617aac33d7c4f031ab772c25b90a2f5d8'
#     params = {'apikey': api_key, 'resource': url}
#     headers = {
#         "Accept-Encoding": "gzip, deflate",
#         "User-Agent": "gzip,  my python requests library example client or username"
#     }
#     response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
#     result = response.json()
#     return result

def analyze_website(url):
    soup = scrape_website(url)
    if not soup:
        return "Unable to scrape website."
    
    domain = url.split('://')[-1].split('/')[0]
    
    analysis = {
        'outdated_software': check_outdated_software(soup),
        'unsecured_forms': check_unsecured_forms(soup),
        'ssl_certificate': check_ssl_certificate(url),
        'security_headers': check_security_headers(url),
        'sql_injection_vulnerability': check_sql_injection(soup, url),
        'xss_vulnerability': check_xss_vulnerability(soup, url),
        'external_links': check_external_links(soup, url),
        'js_libraries': check_js_libraries(soup),
        'broken_links': check_broken_links(soup, url),
        'performance': check_performance(url),
        'seo': check_seo(soup),
        'mobile_friendly': check_mobile_friendly(soup),
        'accessibility': check_accessibility(soup),
        'dns_info': get_dns_info(domain),
        'technologies': detect_technologies(url),
        'content_analysis': analyze_content(soup),
        # 'malware_check': check_malware(url)
    }
    return analysis

def generate_text_report(url, analysis):
    report = []
    report.append("Website Analysis Report\n")
    report.append("="*50 + "\n")
    report.append(f"Website: {url}\n\n")
    
    report.append(f"Outdated Software: {'Yes' if analysis['outdated_software'] else 'No'}\n")
    report.append(f"Unsecured Forms: {len(analysis['unsecured_forms'])} found\n")
    for form in analysis['unsecured_forms']:
        report.append(f"  - Form action: {form.get('action')}\n")
    
    report.append(f"SSL Certificate: {'Valid' if analysis['ssl_certificate'] else 'Invalid or Not Found'}\n")
    if analysis['ssl_certificate']:
        report.append(f"  - Issuer: {analysis['ssl_certificate'].get('issuer')}\n")
    
    report.append("Security Headers:\n")
    for header, value in analysis['security_headers'].items():
        report.append(f"  - {header}: {value}\n")
    
    report.append(f"SQL Injection Vulnerability: {'Yes' if analysis['sql_injection_vulnerability'] else 'No'}\n")
    report.append(f"XSS Vulnerability: {'Yes' if analysis['xss_vulnerability'] else 'No'}\n")
    
    report.append(f"External Links: {len(analysis['external_links'])} found\n")
    for link in analysis['external_links']:
        report.append(f"  - {link}\n")
    
    report.append(f"JavaScript Libraries: {len(analysis['js_libraries'])} found\n")
    for lib in analysis['js_libraries']:
        report.append(f"  - {lib}\n")
    
    report.append(f"Broken Links: {len(analysis['broken_links'])} found\n")
    for link, status in analysis['broken_links']:
        report.append(f"  - {link}: {status}\n")
    
    report.append(f"Performance: Load time - {analysis['performance']['load_time']}s, Status code - {analysis['performance']['status_code']}\n")
    
    report.append("SEO Analysis:\n")
    report.append(f"  - Title: {analysis['seo']['title']}\n")
    report.append(f"  - Meta Description: {analysis['seo']['meta_description']}\n")
    for h, count in analysis['seo']['headings'].items():
        report.append(f"  - {h}: {count} found\n")
    report.append(f"  - Alt texts: {analysis['seo']['alt_texts']} found\n")
    
    report.append(f"Mobile Friendly: {'Yes' if analysis['mobile_friendly'] else 'No'}\n")
    
    report.append("Accessibility:\n")
    report.append(f"  - Alt texts: {analysis['accessibility']['alt_texts']} found\n")
    report.append(f"  - Aria labels: {analysis['accessibility']['aria_labels']} found\n")
    report.append(f"  - Missing alt texts: {analysis['accessibility']['missing_alt_texts']} found\n")
    
    report.append("DNS Information:\n")
    for record, values in analysis['dns_info'].items():
        report.append(f"  - {record}: {', '.join(values) if isinstance(values, list) else values}\n")
    
    report.append("Technologies:\n")
    for tech, details in analysis['technologies'].items():
        report.append(f"  - {tech}: {details}\n")
    
    report.append("Content Analysis:\n")
    report.append(f"  - Polarity: {analysis['content_analysis']['polarity']}\n")
    report.append(f"  - Subjectivity: {analysis['content_analysis']['subjectivity']}\n")
    
    # report.append("Malware Check:\n")
    # report.append(f"  - {analysis['malware_check']}\n")
    
    report.append("="*50 + "\n")

    with open('xv_website_analysis_report.txt', 'w') as f:
        f.write("\n".join(report))
    print("Report generated: xv_website_analysis_report.txt")

# URL to analyze
url = 'https://studyaffairs.ng/'
analysis = analyze_website(url)
print(analysis)
generate_text_report(url, analysis)
