import unittest
from typing import Tuple, Optional

import pytest
from haystack import Document

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.index.web_resources_pipeline import GenerateTitleAndDescription


@pytest.mark.ollama
class GenerateTitleAndDescriptionTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.generator_config = GeneratorConfig().apply_summarizing_default()
        self.component = GenerateTitleAndDescription(generator_config=self.generator_config)

    def _run_component(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        doc = Document(content=content)
        doc.meta["status_code"] = 200
        result = self.component.run(documents=[doc])["documents"][0]
        return result.meta.get("title", None), result.meta.get("description", None)

    def test_javascript1(self):
        title, description = self._run_component("""
;(function (name, definition) {
  var LANGUAGE = {"2024-12-31":"New Year\u0027s Eve","2023-11-11":"Veterans Day","2023-11-10":"Veterans Day (Observed)","2018-05-28":"Memorial Day","2020-05-10":"Mother\u0027s Day","2024-07-04":"Independence Day","2023-02-20":"Presidents\u0027 Day","2019-04-21":"Easter","2022-09-05":"Labor Day","2024-01-15":"Martin Luther King Jr. Birthday","2018-11-22":"Thanksgiving Day","2020-02-17":"President\u0027s Day","2025-05-26":"Memorial Day","2022-01-01":"New Year\u0027s Day","2021-01-18":"Martin Luther King Jr Day","2024-12-25":"Christmas Day","2024-12-24":"Christmas Eve","2020-05-25":"Memorial Day","2021-04-04":"Easter","2025-09-01":"Labor Day","2025-11-27":"Thanksgiving Day","2019-02-18":"Presidents\u0027 Day","2018-11-12":" ","2021-10-31":"Halloween","2022-05-30":"Memorial Day","2024-01-01":"New Year\u0027s Day","2024-06-19":"Juneteenth","2022-11-24":"Thanksgiving Day","2018-11-11":"Veterans Day","2024-03-29":"Good Friday","2020-11-11":"Veterans Day","2021-02-14":"Valentine\u0027s Day","2021-02-15":"President\u0027s Day ","2025-11-11":"Veterans Day","2022-01-17":"Martin Luther King Jr. Day","2018-01-01":"New Year’s Day","2023-05-29":"Memorial Day","2024-09-02":"Labor Day","2021-12-25":"Christmas Day","2022-12-26":"Christmas Holiday","2025-02-17":"Presidents\u0027 Day","2021-12-24":"Christmas Eve","2022-12-25":"Christmas Day","2021-06-20":"Father\u0027s Day","2023-11-23":"Thanksgiving Day","2019-11-11":"Veterans Day","2022-07-04":"Independence Day","2020-10-31":"Halloween","2020-02-14":"Valentine\u0027s Day","2019-11-28":"Thanksgiving Day","2024-05-27":"Memorial Day","2018-09-03":"Labor Day","2023-09-04":"Labor Day","2023-01-01":"New Year\u0027s Day","2019-05-27":"Memorial Day","2021-12-31":"New Year\u0027s Eve","2024-11-28":"Thanksgiving Day","2021-07-04":"Independence Day","2018-07-04":"Independence Day","2023-01-02":"New Year\u0027s Day (Observed)","2021-11-25":"Thanksgiving","2023-06-19":"Juneteenth","2019-09-02":"Labor Day","2020-06-21":"Father\u0027s Day","2021-05-31":"Memorial Day","2025-04-18":"Good Friday","
""")
        self.assertTrue(len(title) > 10, title)
        self.assertTrue(len(description) > 60, description)

    def test_css1(self):
        title, description = self._run_component("""
.online-unban-cookie-mask{display:-webkit-box;display:-ms-flexbox;display:flex;position:fixed;-webkit-box-align:center;-ms-flex-align:center;align-items:center;-webkit-box-pack:center;-ms-flex-pack:center;background:rgba(0,0,0,.6);inset:0;justify-content:center;z-index:9999}.online-unban-cookie-mask .online-unban-cookie-content{background-color:#fff;border-radius:8px;-webkit-box-sizing:border-box;box-sizing:border-box;padding:24px;width:670px}.online-unban-cookie-mask .online-unban-cookie-content .online-unban-cookie-title{color:#0f294d;font-size:20px;font-weight:500;line-height:26px;margin-bottom:16px}.online-unban-cookie-mask .online-unban-cookie-content .online-unban-cookie-text{color:#455873;font-size:14px;line-height:22px;margin-bottom:24px}.online-unban-cookie-mask .online-unban-cookie-content .online-unban-cookie-text>span>span{display:block;margin-top:15px}.online-unban-cookie-mask .online-unban-cookie-content .online-unban-cookie-text>span>span span{display:block}.online-unban-cookie-mask .online-unban-cookie-content #online-unban-cookie-button{cursor:pointer;text-align:end}.online-unban-cookie-mask .online-unban-cookie-content #online-unban-cookie-button span{background:#3264ff;border-radius:4px;-webkit-box-sizing:border-box;box-sizing:border-box;color:#fff;display:inline-block;font-size:16px;font-weight:500;height:38px;line-height:38px;padding:0 16px}
""")
        self.assertTrue(len(title) > 10, title)
        self.assertTrue(len(description) > 60, description)

    def test_html1(self):
        title, description = self._run_component("""
<html><head><title>Official Title of the Site</title></head><body>
""")
        self.assertEqual("Official Title of the Site", title)
        self.assertTrue(len(description) > 20, description)
