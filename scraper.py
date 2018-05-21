"""
1) url extentions
2) login forms
3) parse original domain in text and headers
4) mb js miners
"""

import csv
import os
import re

import bs4 as bs
import requests


blacklist = ['html', 'php', 'jpg', 'png', 'css', 'py', 'eot', 'columns',
             'ico', 'js', 'dtd', 'gif', 'svg', 'php3', 'xml', 'asp',
             'min', 'ttf', 'woff', 'aspx', 'jsp', 'htm', 'cgi',
             'com', 'org', 'net', 'uk', 'bmp', 'JPG', 'jpeg']

whitelist = [
    '0.9', '386', '3dsx', '8xp', 'a6p', 'abs', 'acc', 'accde', 'acx', 'aepl', 'aex', 'agt', 'aif', 'air',
    'ali', 'apk', 'app', 'application', 'appref-ms', 'appx', 'aru', 'atm', 'aut', 'axf', 'azw2', 'bas',
    'bat', 'bhx', 'bi?', 'bin', 'bkd', 'blf', 'bll', 'bmw', 'boo', 'bpp', 'bps', 'bqf', 'btm', 'buk', 'bup',
    'bxz', 'c', 'cac', 'capxml', 'cas', 'cc', 'ce0', 'ceo', 'cfxxe', 'chm', 'cih', 'cla', 'class', 'cmd',
    'com', 'command', 'cpl', 'cpp', 'ctbl', 'ctl', 'cxp', 'cxq', 'cyw', 'dbd', 'dbr', 'deb', 'delf', 'dev',
    'dex', 'dexe', 'dlb', 'dld', 'dli', 'dll', 'dllx', 'dol', 'dom', 'drv', 'dsp', 'dx', 'dxz', 'dyv', 'dyz',
    'eham', 'elf', 'exe', 'exe1', 'exec', 'exe_renamed', 'exp', 'ezt', 'fag', 'farrun', 'fjl', 'fmx', 'fnr',
    'fox', 'fpx', 'fqy', 'frm', 'fuj', 'fxp', 'g3a', 'gambas', 'gpe', 'gpu', 'gtp', 'gzquar', 'hlp', 'hlw',
    'hsq', 'hta', 'hts', 'iconfig', 'ifs', 'ijc', 'ime', 'int', 'irx', 'iva', 'iws', 'jar', 'jax', 'js', 'jse',
    'kcd', 'kmd', 'le', 'let', 'lik', 'lit', 'lkh', 'lku', 'lnk', 'lok', 'lpaq5', 'mcq', 'mex', 'mexw32', 'mfu',
    'mjg', 'mjz', 'msc', 'msi', 'msp', 'n', 'ndr', 'nexe', 'n-gage', 'nls', 'ns2p', 'nt', 'nxe', 'oar', 'oat',
    'ocx', 'odex', 'osa', 'osx', 'out', 'ozd', 'paf.exe', 'part1.exe', 'pcx', 'pe', 'pef', 'pex', 'pgm', 'php3',
    'pid', 'pif', 'pl', 'plc', 'pmb', 'ppp9', 'ppz9', 'pr', 'prc', 'prg', 'prx', 'pva', 'pwz', 'pyd', 'pyz', 'pyzw',
    'qit', 'qpkg', 'qpx', 'qrn', 'r', 'rbtx', 'rhk', 'rna', 'rpm', 'rsc_tmp', 'rtl', 'run', 'rxe', 'ryb', 's2a',
    's7p', 'scr', 'self', 'shb', 'sh', 'shs', 'sis.dm', 'sisx.dm', 'ska', 'sko', 'smm', 'smtmp', 'som', 'sop', 'spam',
    'sqr', 'ssy', 'stx', 'swf', 'sxx', 'sys', 'tcp', 'tgz', 'tko', 'tps', 'trs', 'tsa', 'tti', 'txs', 'tzx', 'upa',
    'uzy', 'vb', 'vba', 'vbe', 'vbs', 'vbx', 'vexe', 'vxd', 'vzr', 'widget', 'wie', 'wince', 'wiz', 'wlpginstall',
    'wmf', 'ws', 'wsc', 'wsh', 'wwe', 'x', 'x86', 'xap', 'xdu', 'xip', 'xir', 'xlm', 'xlnk', 'xlv', 'xnt', 'xnxx',
    'xtbl', 'zix', 'zpkg', 'zvz', 'lua', 'luac'
]

pattern = r'(?:[A-z0-9\-.]+\.[A-z]+|(?:\d{1,3}\.){3}\d{1,3})(?::[0-9]{1,5})?(?:\/[A-z0-9_\-+%.]+)+\.[A-Za-z]+'
urlregex = re.compile(pattern, re.I | re.U)

with open('otherlinks.txt') as links, open('otherlinksresults.csv', 'w', 0) as rl:
    reader = csv.reader(links, delimiter=",")
    for row in reader:
        r = None
        reason = 'OK'
        try:
            r = requests.get(row[3],
                             allow_redirects=True,
                             headers={
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'},
                timeout=20)
        except requests.exceptions.SSLError:
            reason = 'Invalid cert'
            continue
        except requests.exceptions.ConnectionError:
            reason = 'Could not connect'
            continue
        except requests.exceptions.Timeout:
            reason = 'Timeout'
            continue
        except requests.exceptions.HTTPError:
            reason = 'Unsuccessful status code'
            continue
        except requests.exceptions.ChunkedEncodingError:
            reason = 'Encoding Error'
            continue
        except requests.exceptions.TooManyRedirects:
            reason = 'TooManyRedirects'
            continue
        except Exception:
            reason = 'Unknown'
            continue
        text = r.text
        content = r.content
        soup = bs.BeautifulSoup(content, 'lxml')
        domain = str(row[0])
        mentions = re.findall(domain.split('.')[0], content)
        urls = re.findall(pattern, content)
        files = ''
        tot = 0
        dl_urls = []
        for url in urls:
            splitext = url.rsplit('.', 1)
            tot = 0
            if len(splitext) < 2:
                ext = ''
            else:
                ext = splitext[1].strip('\\')
            if ext == '' or ext in blacklist:
                continue
            elif ext in whitelist:
                tot += 1
            print(url)
            dl_urls.append(url)
        exes, zips, swfs, bins, dlls, shs = 0, 0, 0, 0, 0, 0
        for url in dl_urls:
            if url.endswith('.exe'):
                exes += 1
            elif url.endswith('.zip'):
                zips += 1
            elif url.endswith('.swf'):
                swfs += 1
            elif url.endswith('.bin'):
                bins += 1
            elif url.endswith('.dll'):
                dlls += 1
            elif url.endswith('.sh'):
                shs += 1
        forms = soup.find_all('form')

        result = row
        result.extend([str(len(set(dl_urls))), str(tot), str(exes), str(
            zips), str(swfs), str(bins), str(dlls), str(shs), str(
            len(forms)), str(len(mentions)), reason])
        rl.write(','.join(result) + '\n', )
