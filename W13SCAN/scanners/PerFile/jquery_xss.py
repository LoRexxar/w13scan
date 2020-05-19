#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: jquery_xss.py
@time: 2020/5/19 16:49
@desc:
'''

import re

from lib.core.enums import VulType, PLACE
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Jquery Xss'

    def check_jquery(self):
        jquery_reg = r"jquery-(\d\.\d*)\.[\w\.\_]*\.js"

        texts = re.findall(jquery_reg, self.response.text, re.M | re.I)

        if texts:

            version = texts[0]

            v1 = int(version.split('.')[0])
            v2 = int(version.split('.')[1])

            if v1 < 3:
                return True
            elif v1 == 3 and v2 < 5:
                return True

        return False

    def audit(self):

        vul_reg = [
            r"(\.html\([^\)]\))"
        ]

        if self.check_jquery():

            for _ in vul_reg:
                text = re.findall(_, self.response.text, re.M | re.I)
                issuc = False

                if text:
                    for t in set(text):
                        ignores = ['function']
                        iscontinue = True

                        for i in ignores:
                            if i in t:
                                iscontinue = False
                                break
                        if not iscontinue:
                            continue

                        result = ResultObject(self)
                        result.init_info(self.requests.url, "页面中存在.HTML绕过", VulType.SENSITIVE)
                        result.add_detail("payload探测", self.requests.raw, self.response.raw,
                                          "根据正则:{} 发现敏感信息:{}".format(_, text), "", "", PLACE.GET)
                        self.success(result)
                        issuc = True
                        break

                if issuc:
                    break


