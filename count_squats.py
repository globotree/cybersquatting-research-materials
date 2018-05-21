import csv
import json
import os.path

import requests

startdir = 'moz500'
filenames = os.listdir(startdir)


def check_domain(original, url):
    stripped_domain = url.replace(
        'http://', '').replace('https://', '').split('/')[0]
    if stripped_domain == original or stripped_domain.endswith(original):
        return True
    else:
        return False


with open('bigresults.csv', 'w') as csvfile, open('moz500.txt', 'r') as scannedfile:
    i = 0
    scanned_domains = scannedfile.read().split('\n')
    fieldnames = ['original', 'similar domain',
                  'score', 'redirect', 'verdict', 'reason', 'fuzzer']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for filename in filenames:
        start_file = os.path.join(startdir, filename)
        with open(start_file) as f:
            try:
                if os.path.getsize(start_file):
                    scan = json.loads(f.read())
                else:
                    scan = {}
            except ValueError:
                print('Error: {}'.format('-' * 30))
            original = start_file.split('/')[1][:-4]
            if original in scanned_domains:
                continue
            domaininfo = {}
            i = 0
            for index, domain in enumerate(scan):
                if scan[index]['fuzzer'] != 'original*':
                    score = str(scan[index].get('ssdeep-score', 0))
                    domain_name = scan[index]['domain-name']
                    domaininfo = {
                        'original': original,
                        'similar domain': domain_name,
                        'score': score,
                        'fuzzer': scan[index]['fuzzer']}
                    i += 1
                    print('Trying #{}'.format(i))
                    try:
                        r = requests.get("http://{}".format(domain_name),
                                         allow_redirects=True,
                                         headers={
                                             'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'},
                                         timeout=20)
                        reason = r.reason
                    except requests.exceptions.SSLError:
                        reason = 'Invalid cert'
                        r = None
                    except requests.exceptions.ConnectionError:
                        reason = 'Could not connect'
                        r = None
                    except requests.exceptions.Timeout:
                        reason = 'Timeout'
                        r = None
                    except requests.exceptions.HTTPError:
                        reason = 'Unsuccessful status code'
                        r = None
                    except requests.exceptions.ChunkedEncodingError:
                        reason = 'Encoding Error'
                        r = None
                    except requests.exceptions.TooManyRedirects:
                        reason = 'TooManyRedirects'
                        r = None
                    except Exception:
                        reason = 'Unknown'
                        r = None

                    if not r:
                        verdict = 'down'
                        domaininfo.update({
                            'redirect': 'No',
                            'verdict': verdict,
                            'reason': reason
                        })
                    else:
                        if check_domain(original, r.url):
                            verdict = 'Legitimate'
                            domaininfo.update({
                                'redirect': 'Original',
                                'verdict': verdict,
                                'reason': reason
                            })
                        else:
                            verdict = 'Potentially malicious'
                            domaininfo.update({
                                'redirect': r.url,
                                'verdict': verdict,
                                'reason': reason
                            })
                    writer.writerow(domaininfo)
