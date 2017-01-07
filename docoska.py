#!/use/bin/env python

import os, logging
from doco import Doco

from flask import Flask, request, jsonify, make_response
app = Flask(__name__)

config = "doco.conf"

@app.route('/count/', methods=['GET'])
def count():
    d = Doco(api="count")
    d.setloglevel(level="DEBUG")
    if os.path.exists(config):
        d.parse_config(config)
    else:
        logging.error("Config file not found.")
        return make_response("Internal Server Error",500)

    if request.method == 'GET':
        #  access=monthly(default)|daily
        access = request.args.get("access")
        if access in ("daily", "monthly"):
            if access == "daily":
                access = "DailyAccess"
            elif access == "monthly":
                access = "MonthlyAccess"
            d.count(access=access)
        elif not access:
            d.count(access="MonthlyAccess")
        else:
            logging.error("Invalid access type")

    # todo: output transform
    if d.result:
        return d.result.text

    return make_response("Bad Request",400)

# todo: more REST like route
@app.route('/search/', methods=['GET'])
def search():
    res = None
    rdict = {
            "status":"",
            "message":"",
    }
    d = Doco(api="search")
    d.setloglevel(level="DEBUG")
    if os.path.exists(config):
        d.parse_config(config)
    else:
        logging.error("Config file not found.")
        rdict["status"] = 500
        rdict["message"] = "Internal Server Error"

    if not d.cache:
        d.setcache()

    if request.method == 'GET':
        ip = request.args.get("ip")
        # todo: validate ip
        if not ip:
            rdict["status"] = 400
            rdict["message"] = "The parameter 'ip' is missing"

        # out=json(default)|xml|summary|jsummary
        out = request.args.get("out")
        resform = "json"
        if not out:
            d.output = "json"
        elif out in ("json", "xml"):
            d.output = out
            resform = d.output
        elif out in ("summary", "jsummary"):
            d.output = out
        else:
            rdict["status"] = 400
            rdict["message"] = "Invalid output type."

        # execute search 
        if not rdict["status"]:
            d.search(ip, resform=resform)
            if d.output == "json":
                res = jsonify(d.result.json())
            elif d.output == "xml":
                res = d.result.text
            elif d.output in ("summary", "jsummary"):
                res = d.summary()

    if not res:
        if not rdict["status"]:
            rdict["status"] = 400
            rdict["message"] = "Invalid request."
        res = jsonify(rdict)
        res.status_code = rdict["status"]

    return res 

if __name__ == '__main__':
    app.run(debug=True)
