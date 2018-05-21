import time
import requests

submit_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
report_url = 'https://www.virustotal.com/vtapi/v2/url/report'

API_KEY = ''


def scan_url(url):
    params = {'apikey': API_KEY, 'url': url}
    response = requests.post(submit_url, data=params)
    if response.status_code == 204:
        print('sleeping 61 secs')
        time.sleep(61)
        response = scan_url(url)
    return response


def get_report(url):
    params = {'apikey': API_KEY, 'resource': url}
    response = requests.get(report_url, params=params)
    if response.status_code == 204:
        print('sleeping 61 secs')
        time.sleep(61)
        response = get_report(url)
    return response


urls = []

with open('vturldataset.txt') as dataset:
    for line in dataset:
        url = line.strip()
        urls.append(url)
with open('vtresults.txt', 'w', 0) as f:
    i = 0
    for url in urls:
        i += 1
        try:
            submit_result = scan_url(url)
            print('URL #{} submitted successfully ({})'.format(str(i), url))
            time.sleep(15)
            report = get_report(url)
            time.sleep(15)
            print('report obtained successfully')
            try:
                positives = report.json()['positives']
            except ValueError as e:
                print('empty response: {}'.format(str(e)))
                positives = 0
            f.write('{},{}\n'.format(url, str(positives)))
        except Exception:
            f.write('{},{}\n'.format(url, str(0)))
