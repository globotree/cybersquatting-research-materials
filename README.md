# Kromtech Security Center Cybersquatting Research materials

This is a set of custom scripts written and used to conduct research.

### Here is the main flow:

1) Run research.py

It takes moz500 list of popular domains and first 10000 of majestic million list.
It generates to folders for each of the lists and for each domain it generates a file in a corresponding folder with results from a tool called dnstwist in json format.

2) Run count_squats.py

This script will generate bigresults.csv with all results for domains in moz500 list with final links it got redirected to, verdict(if it's legitimate, down or potentially malicious), the reason why it gave that verdict, fuzzer name and ssdeep site similarity score from dnstwist results.

3) Then we put all "Potentially malicious" links from bigresults.csv to vturldataset.txt and ran virustotalscanner.py

You'll need to supply your own Virus Total API key in order for the script to work.
The script will generate vtresults.txt with url scanned and number of positives in csv format.

4) Run scraper.py

The script will scrape all links in otherlinks.txt, count forms, mentions of original domains in body of the site, urls to download files and interesting ones (like exe, sh, etc.) separately.
The results will be stored in otherlinksresults.csv in csv format.
