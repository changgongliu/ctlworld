# !/usr/bin/python
# -*- coding:utf-8 -*-

import smtplib
from_addr = "changgongliu@163.com"#input('From:')
passwd = 'test'#input('Password:')
#to_addr = 'changgongliu@163.com'#input('To:')
smtp_server = "smtp.163.com"
try:
    server = smtplib.SMTP()
    server.connect(smtp_server)
    server.set_debuglevel(1)
    server.login(from_addr, passwd)
    #server.quit()
except Exception, e:
    print str(e)
