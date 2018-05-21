import json
import os
import os.path
import requests

moz500dir = 'moz500'
majestic10kdir = 'majestic_million'
dir_to_use = majestic10kdir

with open('count_results_per_domain_{}.txt'.format(dir_to_use), 'w') as drf, open('results_{}.txt'.format(dir_to_use), 'w') as f:
    scanned_domains = 0
    scanned_companies = 0
    for item in os.listdir(dir_to_use):
        scanned_companies += 1
        filename = os.path.join(dir_to_use, item)
        with open(filename) as f:
            try:
                if os.path.getsize(filename):
                    scan = json.loads(f.read())
                else:
                    scan = {}
            except ValueError:
                print("Error: {}{}".format(item, '-' * 30))
            domains = []
            original = ''
            for index, domain in enumerate(scan):
                if scan[index]['fuzzer'] != "original*":
                    domains.append(scan[index]['domain-name'])
                score = scan[index].get('ssdeep-score', 0)
            drf.write('{},{}\n'.format(item[:-4], len(domains)))
        scanned_domains += len(domains)
    f.write('Scanned companies: {}\n'.format(scanned_companies))
    f.write('Total scanned domains with permutations: {}\n'.format(
        scanned_domains))
    f.write('Total scanned domains: {}\n'.format(
        scanned_domains + scanned_companies))
