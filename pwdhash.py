#! /usr/bin/env python3

import hmac
import base64
import getpass
import hashlib
import string
import re
import argparse
import os
import sys

PREFIX = '@@'
PWDHASH2_SALT_ENV = 'PWDHASH2_SALT'
PWDHASH2_ITERATIONS_ENV = 'PWDHASH2_ITERATIONS'
DUALTLDS = [
    'ab.ca', 'ac.ac', 'ac.at', 'ac.be', 'ac.cn', 'ac.il', 'ac.in', 'ac.jp',
    'ac.kr', 'ac.nz', 'ac.th', 'ac.uk', 'ac.za', 'adm.br', 'adv.br', 'agro.pl',
    'ah.cn', 'aid.pl', 'alt.za', 'am.br', 'arq.br', 'art.br', 'arts.ro',
    'asn.au', 'asso.fr', 'asso.mc', 'atm.pl', 'auto.pl', 'bbs.tr', 'bc.ca',
    'bio.br', 'biz.pl', 'bj.cn', 'br.com', 'cn.com', 'cng.br', 'cnt.br',
    'co.ac', 'co.at', 'co.il', 'co.in', 'co.jp', 'co.kr', 'co.nz', 'co.th',
    'co.uk', 'co.za', 'com.au', 'com.br', 'com.cn', 'com.ec', 'com.fr',
    'com.hk', 'com.mm', 'com.mx', 'com.pl', 'com.ro', 'com.ru', 'com.sg',
    'com.tr', 'com.tw', 'cq.cn', 'cri.nz', 'de.com', 'ecn.br', 'edu.au',
    'edu.cn', 'edu.hk', 'edu.mm', 'edu.mx', 'edu.pl', 'edu.tr', 'edu.za',
    'eng.br', 'ernet.in', 'esp.br', 'etc.br', 'eti.br', 'eu.com', 'eu.lv',
    'fin.ec', 'firm.ro', 'fm.br', 'fot.br', 'fst.br', 'g12.br', 'gb.com',
    'gb.net', 'gd.cn', 'gen.nz', 'gmina.pl', 'go.jp', 'go.kr', 'go.th',
    'gob.mx', 'gov.br', 'gov.cn', 'gov.ec', 'gov.il', 'gov.in', 'gov.mm',
    'gov.mx', 'gov.sg', 'gov.tr', 'gov.za', 'govt.nz', 'gs.cn', 'gsm.pl',
    'gv.ac', 'gv.at', 'gx.cn', 'gz.cn', 'hb.cn', 'he.cn', 'hi.cn', 'hk.cn',
    'hl.cn', 'hn.cn', 'hu.com', 'idv.tw', 'ind.br', 'inf.br', 'info.pl',
    'info.ro', 'iwi.nz', 'jl.cn', 'jor.br', 'jpn.com', 'js.cn', 'k12.il',
    'k12.tr', 'lel.br', 'ln.cn', 'ltd.uk', 'mail.pl', 'maori.nz', 'mb.ca',
    'me.uk', 'med.br', 'med.ec', 'media.pl', 'mi.th', 'miasta.pl', 'mil.br',
    'mil.ec', 'mil.nz', 'mil.pl', 'mil.tr', 'mil.za', 'mo.cn', 'muni.il',
    'nb.ca', 'ne.jp', 'ne.kr', 'net.au', 'net.br', 'net.cn', 'net.ec',
    'net.hk', 'net.il', 'net.in', 'net.mm', 'net.mx', 'net.nz', 'net.pl',
    'net.ru', 'net.sg', 'net.th', 'net.tr', 'net.tw', 'net.za', 'nf.ca',
    'ngo.za', 'nm.cn', 'nm.kr', 'no.com', 'nom.br', 'nom.pl', 'nom.ro',
    'nom.za', 'ns.ca', 'nt.ca', 'nt.ro', 'ntr.br', 'nx.cn', 'odo.br',
    'on.ca', 'or.ac', 'or.at', 'or.jp', 'or.kr', 'or.th', 'org.au',
    'org.br', 'org.cn', 'org.ec', 'org.hk', 'org.il', 'org.mm', 'org.mx',
    'org.nz', 'org.pl', 'org.ro', 'org.ru', 'org.sg', 'org.tr', 'org.tw',
    'org.uk', 'org.za', 'pc.pl', 'pe.ca', 'plc.uk', 'ppg.br', 'presse.fr',
    'priv.pl', 'pro.br', 'psc.br', 'psi.br', 'qc.ca', 'qc.com', 'qh.cn',
    're.kr', 'realestate.pl', 'rec.br', 'rec.ro', 'rel.pl', 'res.in', 'ru.com',
    'sa.com', 'sc.cn', 'school.nz', 'school.za', 'se.com', 'se.net', 'sh.cn',
    'shop.pl', 'sk.ca', 'sklep.pl', 'slg.br', 'sn.cn', 'sos.pl', 'store.ro',
    'targi.pl', 'tj.cn', 'tm.fr', 'tm.mc', 'tm.pl', 'tm.ro', 'tm.za', 'tmp.br',
    'tourism.pl', 'travel.pl', 'tur.br', 'turystyka.pl', 'tv.br', 'tw.cn',
    'uk.co', 'uk.com', 'uk.net', 'us.com', 'uy.com', 'vet.br', 'web.za',
    'web.com', 'www.ro', 'xj.cn', 'xz.cn', 'yk.ca', 'yn.cn', 'za.com']


def str_ROL(s, n):
    n = n % len(s)
    return s[n:] + s[:n]


def extract_domain(uri):
    host = re.sub(r'https?:\/\/', '', uri)
    host = host.split('/')[0]
    host = host.split('.')
    if len(host) >= 3 and '.'.join(host[-2:]) in DUALTLDS:
        host = host[-3:]
    else:
        host = host[-2:]
    return '.'.join(host)


def apply_constraints(digest, size, alnum=False):
    # leave room for some extra characters
    start_size = max(size - 4, 0)
    result = digest[:start_size]
    extras = list(reversed(digest[start_size:]))

    def cond_add_extra(f, candidates):
        n = ord(extras.pop()) if extras else 0
        if any(f(x) for x in result):
            return chr(n)
        else:
            return candidates[n % len(candidates)]

    result += cond_add_extra(str.isupper, string.ascii_uppercase)
    result += cond_add_extra(str.islower, string.ascii_lowercase)
    result += cond_add_extra(str.isdigit, string.digits)
    if re.search(r'\W', result) and not alnum:
        result += extras.pop() if extras else chr(0)
    else:
        result += '+'
    if alnum:
        while re.search(r'\W', result):
            c = cond_add_extra(lambda x: False, string.ascii_uppercase)
            result = re.sub(r'\W', c, result, count=1)
    return str_ROL(result, ord(extras.pop()) if extras else 0)


def project_to_ascii(s):
    return "".join(chr(ord(x) & 0xff) for x in s)


def pwdhash2(domain, password, iterations, salt):
    #NOTE: What should be done with 'äöü' or 'проверка'?
    size = len(PREFIX) + len(password)
    digest = hashlib.pbkdf2_hmac(
        "sha256", (password+salt).encode(), domain.encode(), iterations, (size * 2 // 3) + 16)
    b64digest = base64.b64encode(digest).decode("ascii")[:-2]  # remove padding
    return apply_constraints(b64digest, size, not password or password.isalnum())


def pwdhash(domain, password):
    domain = domain.encode('utf-8')
    password = project_to_ascii(password).encode('utf-8')
    digest = hmac.new(password, domain, 'md5').digest()
    b64digest = base64.b64encode(digest).decode("utf-8")[:-2]  # remove padding
    size = len(PREFIX) + len(password)
    return apply_constraints(b64digest, size, not password or password.isalnum())


def _check_iterations_and_salt(iterations, salt):
    if salt is None:
        sys.exit('Please define {0!r} environment variable, or specify --salt.'.format(PWDHASH2_SALT_ENV))
    if iterations is None:
        sys.exit('Please define {0!r} environment variable, or specify --iterations.'.format(PWDHASH2_ITERATIONS_ENV))

def _args_parser(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-s', '--stdin', action='store_true',
                        help='Get password from stdin instead of prompt. Default is prompt')
    parser.add_argument('-t', '--twice', action='store_true',
                        help='Ask password twice, and check both are the same. Default is once')
    parser.add_argument('-c', '--copy', action='store_true',
                        help='Copy hash to clipboard instead of displaying it. Default is display')
    parser.add_argument('-n', action='store_true',
                        help='Do not print the trailing newline')
    parser.add_argument('domain', help='the domain or uri of the site')
    return parser

def _add_v2_params(parser):
    parser.add_argument('--salt', type=str, help='Salt',
                        default=os.getenv(PWDHASH2_SALT_ENV))
    parser.add_argument('--iterations', type=int, help='How many iterations',
                        default=os.getenv(PWDHASH2_ITERATIONS_ENV))

def _process(parser, cli_args, version=None):
    args = parser.parse_args(cli_args)
    version = version or args.version

    domain = extract_domain(args.domain)

    if version == 2:
        _check_iterations_and_salt(args.iterations, args.salt)

    if args.stdin:
        password = sys.stdin.readline().strip()
    else:
        password = getpass.getpass()
        if args.twice:
            password2 = getpass.getpass('Enter password again:')
            if password != password2:
                sys.exit('ERROR: Passwords did not match.')

    if version == 1:
        result = pwdhash(domain, password)
    else:
        result = pwdhash2(domain, password, args.iterations, args.salt)

    if args.copy:
        try:
            import pyperclip
            pyperclip.copy(result)
        except ImportError:
            print("ERROR: Please install pyperclip. Password wasn't copied to clipboard.")
    else:
        print(result, end='' if args.n else '\n')


def v1_or_v2(cli_args):
    """Called from python pwdhash.py"""
    parser = _args_parser('Computes PwdHash1 or PwdHash2')
    parser.add_argument('-v', '--version', type=int,
                        choices=[1, 2], default=1, help='Use PwdHash 1 or 2. Default is 1')
    _add_v2_params(parser)
    _process(parser, cli_args)


def v1(cli_args=None):
    """Called from pwdhash script, when installed as package"""
    parser = _args_parser('Computes PwdHash1')
    _process(parser, cli_args, 1)


def v2(cli_args=None):
    """Called from pwdhash2 script, when installed as package"""
    parser = _args_parser('Computes PwdHash2')
    parser.version = 2
    _add_v2_params(parser)
    _process(parser, cli_args, 2)

if __name__ == '__main__':
    v1_or_v2(None)
