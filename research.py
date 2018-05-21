import csv
import os.path
import sys
from subprocess import Popen, PIPE


def scan_moz_500():
    with open("top500.domains.02.18.csv") as csvfile:
        reader = csv.DictReader(csvfile, delimiter=",")
        i = 0
        for row in reader:
            i += 1
            row["URL"] = row["URL"][:-1]
            print('#{} {}'.format(i, row["URL"]))
            try:
                p = Popen(["python", "dnstwist/dnstwist.py", "-j", "-g", "-s", "-r",
                           "-m", row["URL"]], stdin=PIPE, stdout=PIPE, stderr=PIPE)
                output, err = p.communicate()
                with open(os.path.join("moz500", "{}.txt".format(row["URL"])), 'w') as f:
                    f.write(output)
            except Exception as e:
                print(e)
                print(sys.exc_info())


def scan_majestic_million():
    with open("majestic_million.csv") as csvfile:
        reader = csv.DictReader(csvfile, delimiter=",")
        i = 0
        for row in reader:
            i += 1
            if i > 10000:
                break
            domain = row["Domain"]
            print('#{} {}'.format(i, domain))
            try:
                p = Popen(["python", "dnstwist/dnstwist.py", "-j", "-g", "-s", "-r",
                           "-m", domain], stdin=PIPE, stdout=PIPE, stderr=PIPE)
                output, err = p.communicate()
                with open(os.path.join("majestic_million", "{}.txt".format(domain)), 'w') as f:
                    f.write(output)
            except Exception as e:
                print(e)
                print(sys.exc_info())


if __name__ == '__main__':
    scan_moz_500()
    scan_majestic_million()
