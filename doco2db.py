#!/usr/bin/env python

import sys
import sqlite3
from bs4 import BeautifulSoup

dbname = "docodata.db"
with open(sys.argv[1], "r") as fh:
    html = fh.read()
    soup = BeautifulSoup(html, "html.parser")
    dataname = soup.find("h4")
    h4 = dataname.find_all_next("h4")
    for h in h4:
        conn = sqlite3.connect(dbname)
        c = conn.cursor()
        try:
            drop_sql = "drop table %s" % h["id"]
            c.execute(drop_sql)
        except sqlite3.OperationalError as e:
            print(e)
        create_sql = "create table %s (code text, data text)" % h["id"]
        c.execute(create_sql)
        table = h.find_next("table")
        header = table.find("tr")
        for rows in header.find_next_siblings("tr"):
            code, data = rows.find_all("td")
            insert = "insert into %s values (\'%s\', \'%s\')" % (h["id"], code.text, data.text)
            c.execute(insert)
        conn.commit()
        select_sql = "select * from %s" % h["id"]
        for r in c.execute(select_sql).fetchall():
            print(r)
        c.close()
        #sys.exit()
