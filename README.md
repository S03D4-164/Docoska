# Docoska
DocoDoco is an IP geolocation API (FREE for personal use) provided by Cyber Area Research,Inc.

This repository contains following python tools.

    doco.py    : Whois like DocoDoco client (for API v5)
    docoska.py : Flask API using doco.py
    doco2db.py : Create sqlite DB from DocoDoco's HTML source.

## Requirements
    Python 3.5.2
    Flask==0.12
    requests==2.12.4
    requests-cache==0.4.13
    defusedxml==0.5.0
    # for doco2db
    beautifulsoup4==4.5.3
And API keys (need to register)

## Quick Start
Clone the reposotory and create a config file as follows:

    [key]
    key1="api key 1"
    key2="api key 2"

You can also set API urls and cache settings in the config file.

    [api]
    search="Search API URL"
    count="Count API URL"

    # Following are default parameters of setcache() method. 
    [cache]
    backend=sqlite      # Other backend is not tested.
    filename=doco_cache # doco_cache.sqlite will be created.
    expire=2592000
    
By default, the tools search "doco.conf" on the same directry.

### CLI tool

    Search API:
    doco.py (IP address|hostname|text file contains IP or hostname)
    
    Access count API:
    doco.py -a (day|month)
    
    options:
    -c [filename]     - Use config file (default: ./doco.conf)
    -d                - Show debug    
    -a (day|month)    - Use Access count API
    
    options for Search API:
    -j                - Whois like summary in Japanese (default output)
    -e                - Whois like summary in English
    -o (json|xml|csv) - Output format
 
### Flask API

    Run server:
    python docoska.py
    
    and server runs on 127.0.0.1:5000.
    
    Request:
    http://127.0.0.1:5000/count/?access=(dayly|monthly)
    http://127.0.0.1:5000/search/?ip=<IP address>&out=(json|xml|summary|jsummary)>
    
