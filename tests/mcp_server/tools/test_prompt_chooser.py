import unittest

import pytest

from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.mcp_server.generator_config import set_generator_config
from shyhurricane.mcp_server.tools.prompt_chooser import extract_targets_and_prompt_title


@pytest.mark.ollama
class PromptChooserTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.titles = [
            "Automated CTF Solver",
            "Automated Hack-the-Box (HTB) CTF Solver",
            "Automated Bug Bounty Hunter",
            "Bug Bounty Hunter Assistant",
            "Automated Penetration Tester",
            "Penetration Tester Assistant",
            "Penetration Test Auditor",
        ]
        set_generator_config(GeneratorConfig().apply_summarizing_default())

    async def test_extract_targets_and_prompt_title_ctf(self):
        targets, prompt_title = await extract_targets_and_prompt_title("Solve the CTF challenge at 192.168.1.1",
                                                                       self.titles)
        self.assertEqual(["192.168.1.1"], targets)
        self.assertEqual("Automated CTF Solver", prompt_title)

    async def test_extract_targets_and_prompt_title_htb(self):
        targets, prompt_title = await extract_targets_and_prompt_title("Solve the HTB challenge at 192.168.1.1",
                                                                       self.titles)
        self.assertEqual(["192.168.1.1"], targets)
        self.assertEqual("Automated Hack-the-Box (HTB) CTF Solver", prompt_title)

    async def test_extract_targets_and_prompt_title_pentest_agent(self):
        targets, prompt_title = await extract_targets_and_prompt_title(
            "Find all the vulns on 192.168.1.1 and 192.168.10.12", self.titles)
        self.assertEqual(["192.168.1.1", "192.168.10.12"], targets)
        self.assertEqual("Automated Penetration Tester", prompt_title)

    async def test_extract_targets_and_prompt_title_pentest_assistant(self):
        targets, prompt_title = await extract_targets_and_prompt_title(
            "Help me find vulns on http://vulnerable.net", self.titles)
        self.assertEqual(["http://vulnerable.net"], targets)
        self.assertEqual("Penetration Tester Assistant", prompt_title)
