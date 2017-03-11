#!/usr/bin/env python

import os, sys, re
from io import StringIO
import socket
import argparse, configparser
import requests, requests_cache
import json, csv, sqlite3
import codecs
import logging
from email.utils import parsedate_tz, mktime_tz
import datetime
import defusedxml.ElementTree as ET

conf = "./doco.conf"
confform = """
Default config path: ./doco.conf
# Please use -c option or edit the source.

Config File Format:
[key]
key1=<API key 1>
key2=<API key 2>
"""

# current API URL
sapi = "https://api.docodoco.jp/v5/search"
capi = "https://api.docodoco.jp/count"

# csv output
fieldnames = [
                    "Input",
                    "IP",
                    "UTCDate",
                    "CountryCode",
                    "LineJName",
                    "CountryJName",
                    "PrefJName",
                    "CityJName",
                    "OrgName",
                    #"OrgAddress",
                    #"OrgPresident",
                    #"CountryAName",
                    #"PrefAName",
                    #"CityAName",
                    #"OrgEnglishName",
                    #"OrgEnglishAddress",
                    "OrgUrl",
                    "OrgDomainName",
                    "OrgDomainType",
                    "DomainName",
                    "DomainType",
                    "BCFlag",
                    "OrgIndependentCode",
                    "ProxyFlag",
                    "OrgIndustrialCategoryL",
                    "OrgIndustrialCategoryM",
                    "OrgIndustrialCategoryS",
                    "OrgIndustrialCategoryT",
                    "OrgIpoType",
                    "OrgCapitalCode",
                    "OrgEmployeesCode",
                    "OrgGrossCode",
        ]


class Doco:
    def __init__(
                    self,
                    search_api=sapi,
                    count_api=capi,
                    key1=None,
                    key2=None,
                    api = None,
                ):
        # api setting
        self.search_api = search_api
        self.count_api = count_api
        self.key1 = key1
        self.key2 = key2

        self.cache = None
        self.loglevel = None

        self.api = "search"
        if api in ("search", "count"):
            self.api = api

        # target ip address
        self.ip = None

        self.resform = None
        self.result = None
        self.output = None

        # for csv output
        self.input = None
        self.csvfile = None
        self.writer = None

        self.jsic = None
        self.docodata = None

    def clear(self, input=False):
        self.ip = None
        self.result = None
        if input:
            self.input = None
        return

    def setcache(
                    self,
                    filename='doco_cache',
                    backend='sqlite',
                    expire=86400,
                    config=None
                ):

        if config:
            if 'filename' in config:
                filename = config['filename']
            if 'backend' in config:
                if config['backend'] in ("sqlite"):
                    backend = config['backend']
            if 'expire' in config:
                expire = config['expire']
        try:
            requests_cache.install_cache(
                cache_name=filename,
                backend=backend,
                expire_after=int(expire))
            self.cache = {
                        "filename":filename,
                        "backend":backend,
                        "expire":expire,
                    }
            logging.debug("cache file -> " + filename)
            logging.debug("cache backend -> " + backend)
            logging.debug("cache expires afrer -> " + str(expire))
        except Exception as e:
            logging.error(e)
            sys.exit()
        return

    def seturl(self):
        if self.api == "search":
            self.url = self.search_api
            self.url += "?format=" + str(self.resform)
            self.url += "&ipadr=" + str(self.ip)
        elif self.api == "count":
            self.url = self.count_api
            self.url += "?data=" + str(self.access)
        else:
            logging.error("Invalid api type")
            self.url = None

        if self.url:
            if self.key1 and self.key2:
                self.url += "&key1=" + str(self.key1)
                self.url += "&key2=" + str(self.key2)
            else:
                logging.error("Invalid api keys")
                self.url = None

        return self.url

    def count(self, access="MonthlyAccess"):
        self.api = "count"
        if access in ("DailyAccess", "MonthlyAccess"):
            self.access = access
        else:
            logging.error("invalid access type.")
            return False

        if self.seturl():
            logging.debug("Query -> " + self.url)
        else:
            logging.error("Failed to make URL.")
            return False

        # don't cache count API results
        with requests_cache.disabled():
            r = requests.get(self.url)
            logging.debug(r.text)
            self.result = r
        return True

    def search(self, ip, resform="json"):
        self.api = "search"
        if re.match("(\d{1,3}\.){3}\d{1,3}", ip):
            self.ip = ip
        else:
            logging.error("Invalid input.")
            return False

        if resform in ("json", "xml"):
            self.resform = resform
        else:
            logging.error("Invalid response format.")
            return False

        if self.seturl():
            logging.debug("Query -> " + self.url)
        else:
            logging.error("Failed to make URL.")
            return False

        r = requests.get(self.url)
        if self.cache:
            logging.debug("Used Cache: {0}".format(r.from_cache))
        else:
            logging.warning("Cannot use cache.")

        if self.resform == "json":
            logging.debug(r.json())
        elif self.resform == "xml":
            logging.debug(r.text)
        self.result = r
        return True

    def mkcsv(
                self,
                bulk=False,
                j=None,
        ):
        if bulk == False:
            self.csvfile = StringIO()
            writer = csv.DictWriter(
                    self.csvfile, 
                    fieldnames=fieldnames,
                    extrasaction='ignore',
                    quoting=csv.QUOTE_ALL,
            )
            self.writer = writer
            self.writer.writeheader()

        # todo: error handling
        if not j:
            j = self.result.json()
            if "date" in self.result.headers:
                date = self.result.headers['date']
                timestamp = mktime_tz(parsedate_tz(date))
                utctime = datetime.datetime.utcfromtimestamp(timestamp)
                j["UTCDate"] = utctime
            for k in (
                    "OrgIndustrialCategoryL",
                    "OrgIndustrialCategoryM",
                    "OrgIndustrialCategoryS",
                    "OrgIndustrialCategoryT",
                    "OrgIpoType",
                    "OrgCapitalCode",
                    "OrgEmployeesCode",
                    "OrgGrossCode",
                    ):
                if j[k]:
                    codes = j[k].split(",")
                    cnames = []
                    for c in codes:
                        cname = self.docodata_lookup(k, c)
                        if cname not in cnames:
                            cnames.append(cname)
                    j[k] = "／".join(cnames)
        if self.input:
            j["Input"] = self.input
        self.writer.writerow(j)
        return

    def summary(self):
        json = self.result.json()
        status = self.result.status_code
        logging.debug(status)
        logging.debug(self.output)
        summary_key = []
        if "status" in json:
            if not json["status"] == 200:
                json["IP"] = self.ip
                #logging.debug(json)
                summary_key = [
                    "IP",
                    "message",
                    "status",
                ]
        else:
            if self.output == "summary":
                summary_key = [
                    "IP",
                    "CountryCode",
                    "TimeZone",
                    "CountryAName",
                    "PrefAName",
                    "CityAName",
                    "OrgEnglishName",
                    "OrgEnglishAddress",
                    "OrgZipCode",
                    "OrgTel",
                    "OrgFax",
                    "OrgUrl",
                    "OrgDomainName",
                    "OrgDomainType",
                    "DomainName",
                    "DomainType",
                ]
            elif self.output == "jsummary":
                summary_key = [
                    "IP",
                    "LineJName",
                    "CountryCode",
                    "TimeZone",
                    "CountryJName",
                    "PrefJName",
                    "CityJName",
                    "OrgName",
                    "OrgPresident",
                    "OrgAddress",
                    "OrgZipCode",
                    "OrgTel",
                    "OrgFax",
                    "OrgUrl",
                    "OrgDomainName",
                    "OrgDomainType",
                    "DomainName",
                    "DomainType",
                    "OrgIndustrialCategoryL",
                    "OrgIndustrialCategoryM",
                    "OrgIndustrialCategoryS",
                    "OrgIndustrialCategoryT",
                    "OrgIpoType",
                    "OrgCapitalCode",
                    "OrgEmployeesCode",
                    "OrgGrossCode",
                ]

        summary = ""
        for k in summary_key:
            # industrial category transform
            if k in (
                    "OrgIndustrialCategoryL",
                    "OrgIndustrialCategoryM",
                    "OrgIndustrialCategoryS",
                    "OrgIndustrialCategoryT",
                    "OrgIpoType",
                    "OrgCapitalCode",
                    "OrgEmployeesCode",
                    "OrgGrossCode",
                    ):
                codes = json[k].split(",")
                cnames = []
                for c in codes:
                    #logging.debug(c)
                    #cname = self.icat_lookup(k, c)
                    cname = self.docodata_lookup(k, c)
                    if cname not in cnames:
                        cnames.append(cname)
                summary += "{0:<25} : {1}\n".format(k, cnames)
            else:
                summary += "{0:<25} : {1}\n".format(k, json[k])
        return summary

    def docodata_lookup(self, key, code):
        if not re.match("^[0-9a-zA-Z]+$", code):
            logging.debug("Invalid code.")
            return
        
        org = {
            "OrgIpoType": "org4",
            "OrgCapitalCode": "org5",
            "OrgEmployeesCode": "org6",
            "OrgGrossCode": "org7",
            "OrgIndustrialCategoryL": "org8",
            "OrgIndustrialCategoryM": "org9",
            "OrgIndustrialCategoryS": "org10",
            "OrgIndustrialCategoryT": "org11",
        }

        conn = sqlite3.connect(self.docodata)
        c = conn.cursor()
        table = org[key]
        sql = "select data from %s where code=\'%s\'" % (table, code)
        data = None
        try:
            data = c.execute(sql).fetchone()
        except Exception as e:
            logging.debug(str(e))
        c.close()
        if data:
            return data[0]
        return

    def icat_lookup(self, category, code):
        l = None
        m = None
        s = None
        t = None
        if category == "OrgIndustrialCategoryL":
            l = code
        elif category == "OrgIndustrialCategoryM":
            m = code
        elif category == "OrgIndustrialCategoryS":
            s = code
        elif category == "OrgIndustrialCategoryT":
            t = code
        cname = None
        #logging.debug("JSIC csv -> " + self.jsic)
        if not os.path.exists(self.jsic):
            logging.warning("JSIC csv not found.")
        elif os.path.exists(self.jsic):
            with open(self.jsic, encoding='shift_jis') as fh:
                reader = csv.reader(fh)
                for row in reader:
                    if row[3] == t:
                        cname = row[4]
                    elif row[3] == "0000" \
                     and row[2] == s:
                        cname = row[4]
                    elif row[3] == "0000" \
                     and row[2] == "000" \
                     and row[1] == m:
                        cname = row[4]
                    elif row[3] == "0000" \
                     and row[2] == "000" \
                     and row[1] == "00" \
                     and row[0] == l:
                        cname = row[4]
        #logging.debug(cname)
        return cname

    def parse_config(self, config):
        cp = configparser.ConfigParser()
        cp.read(config)

        if 'key' in cp:
            keys = cp['key']
            if ('key1' in keys) and ('key2' in keys):
                self.key1 = keys['key1']
                self.key2 = keys['key2']

        if 'cache' in cp:
            cache = cp['cache']
            self.setcache(config=cache)

        if 'api' in cp:
            apis = cp['api']
            if 'search' in apis:
                self.search_api = apis['search']
            if 'count' in apis:
                self.count_api = apis['count']
                
        if 'lookup' in cp:
            lookup = cp['lookup']
            if 'jsic' in lookup:
                self.jsic = lookup['jsic']
            if 'docodata' in lookup:
                self.docodata = lookup['docodata']

        return cp

    def setloglevel(self, level):
        if level == "DEBUG":
            logging.basicConfig(level=logging.DEBUG)
            self.loglevel = level
        else:
            logging.basicConfig(level=logging.WARNING)
            self.loglevel = "WARNING"
        return

def bulk_req(d, arg_is, target):
    lines = target
    logging.debug(lines)

    if d.output == "csv" and d.csvfile == None:
        filename = d.input + "_doco.csv"
        print("output -> " + filename)
        #d.csvfile = open(filename, "w")
        d.csvfile = codecs.open(filename, "wb", "utf-8")
        d.csvfile.write(u'\ufeff')
        writer = csv.DictWriter(
                    d.csvfile, 
                    fieldnames=fieldnames,
                    extrasaction='ignore',
                    quoting=csv.QUOTE_ALL,
        )
        d.writer = writer
        d.writer.writeheader()
        if arg_is == "file":
            d.input = None

    for line in lines:
        line = line.strip()
        logging.debug("line -> " + line)

        line_is, validated_line = validate_arg(line, bulk=True)
        if line_is == 'ip':
            ip = line
            # if input is not hostname, set ip as input
            if not d.input:
                d.input = ip
            status = d.search(ip, resform=d.resform)
            logging.debug(d.input + " -> " + d.ip)
            if d.output in ('summary', 'jsummary'):
                print(d.summary())
            elif d.output == 'csv':
                d.mkcsv(bulk=True)
            elif d.output == 'json':
                print(d.result.json())
            elif d.output == 'xml':
                print(d.result.text)
            d.clear()
        elif line_is == 'hostname':
            d.input = line
            bulk_req(d, line_is, validated_line)
        else:
            if line_is == 'ipv6':
                if d.output in ("summary", "jsummary"):
                    print("IPv6 is not supported -> " + line + "\n")
                else:
                    logging.info("IPv6 is not supported -> " + line + "\n")
            else:
                logging.info("Invalid line -> " + line)

            if d.output == 'csv':
                if not d.input:
                    d.input = line
                if line_is == 'ipv6':
                    d.ip = line
                else:
                    d.ip = "-"
                result = {"Input":d.input,"IP":d.ip}
                d.mkcsv(bulk=True, j=result)
        d.clear(input=True)

    return

def validate_arg(arg, bulk=False):
    arg_is = None
    validated = []
    if os.path.exists(arg):
        if not bulk:
            arg_is = "file"
            fh = open(arg, 'r')
            validated = fh.readlines()
            fh.close()
        else:
            logging.info("skipped.")
    elif re.match("(\d{1,3}\.){3}\d{1,3}", arg):
        arg_is = "ip"
        validated.append(arg)
    elif re.match("[0-9a-fA-F:]+:[0-9a-fA-F]{1,4}$", arg):
        arg_is = "ipv6"
        validated.append(arg)
    else:
        try:
            addr = socket.getaddrinfo(arg, None)
            ips = []
            for a in addr:
                ip = a[4][0]
                if ip not in ips:
                    ips.append(ip)
            if not bulk:
                print(arg + " has ip -> " + ",".join(ips))
            arg_is = "hostname"
            validated = ips
        except Exception as e:
            logging.info(e)
            logging.info("Invalid arg -> " + arg)
            arg_is = "invalid"

    return arg_is, validated

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--debug', '-d', action='store_true')
    ap.add_argument('--access', '-a', required=False,
            choices = ["day", "month"]
    )
    ap.add_argument('--output', '-o', default="jsummary",
            choices = ["summary", "jsummary", "json", "xml", "csv"],
    )
    ap.add_argument('--jp', '-j', action='store_true')
    ap.add_argument('--en', '-e', action='store_true')
    ap.add_argument('--config', '-c', default=conf)
    ap.add_argument('arg', nargs="*")
    args = ap.parse_args()
    if args.jp:
        args.output="jsummary"
    elif args.en:
        args.output="summary"
    args.help = ap.format_usage()
    return args

def main():
    # parse arguments
    args = parse_args()

    d = Doco()
    if args.debug:
        d.setloglevel(level="DEBUG")
    else:
        d.setloglevel(level="WARNING")
    logging.debug(args)

    # parse config file
    if os.path.exists(args.config):
        d.parse_config(args.config)
    else:
        sys.exit("Config file not found." + confform)

    if not (d.key1 and d.key2):
        sys.exit("Please set API keys in config file." + confform)
        
    # count API request
    if args.access:
        access = None
        if args.access == "day":
            access = "DailyAccess"
        elif args.access == "month":
            access = "MonthlyAccess"
        if d.count(access=access):
            # todo: xml parse
            root = ET.fromstring(d.result.text)
            for childs in root:
                for child in childs:
                    print(child.tag, child.attrib, child.text)
                    for c in child:
                        print(c.tag, c.attrib, c.text)
            sys.exit()
        else:
            sys.exit("Count API Request Failed.")

    if not d.cache:
        d.setcache()

    # input type validation -> ip|hostname|file
    arg = None
    if len(args.arg) > 0:
        arg = args.arg[0]
        if len(args.arg) > 1:
            logging.warning("Too many args.")
    else:
        sys.exit(args.help + "No argument.")

    arg_is, validated = validate_arg(arg)
    logging.debug(arg + " is " + arg_is)

    if args.output:
        d.output = args.output
    # API response format
    d.resform = "json"
    if d.output == "xml":
        d.resform = "xml"

    if arg_is == "ip":
        # search API request
        target = validated[0]
        if d.search(target, resform=d.resform):
            logging.debug("status -> " + str(d.result.status_code))
        else:
            sys.exit("Search failed.")

        # output transform
        if d.output == "json":
            print(d.result.json())
        elif d.output == "xml":
            print(d.result.text)
        elif d.output == "csv":
            d.input = target
            d.mkcsv(bulk=False)
            print(d.csvfile.getvalue())
            d.csvfile.close()
        elif d.output in ("summary", "jsummary"):
            summary = d.summary()
            if summary:
                print(summary)

    elif arg_is == "ipv6":
        logging.warning("IPv6 is not supported")
    elif arg_is in ("file", "hostname"):
        d.input = arg
        if arg_is == "file":
            # if input is file, force csv output
            d.output = "csv"

        #bulk_req(d, arg_is, target)
        bulk_req(d, arg_is, validated)
        if d.output == "csv":
            if d.csvfile:
                d.csvfile.close()
    else:
        logging.warning("Invalid input -> " + arg)
        logging.warning("Input must be IP or hostname or list")

    logging.debug("done.")

if __name__ == '__main__':
    main()
