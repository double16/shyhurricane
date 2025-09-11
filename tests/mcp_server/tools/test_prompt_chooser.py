import asyncio
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

    def test_extract_targets_and_prompt_title_ctf(self):
        targets, prompt_title = asyncio.run(extract_targets_and_prompt_title(
            "Solve the CTF challenge at 192.168.1.1",
            self.titles))
        self.assertEqual(["192.168.1.1"], targets)
        self.assertEqual("Automated CTF Solver", prompt_title)

    def test_extract_targets_and_prompt_title_htb(self):
        targets, prompt_title = asyncio.run(extract_targets_and_prompt_title(
            "Solve the HTB challenge at 192.168.1.1",
            self.titles))
        self.assertEqual(["192.168.1.1"], targets)
        self.assertEqual("Automated Hack-the-Box (HTB) CTF Solver", prompt_title)

        targets, prompt_title = asyncio.run(extract_targets_and_prompt_title(
            "Solve the HTB web challenge at http://192.168.1.1:8000. There is only one flag.",
            self.titles))
        self.assertEqual(["http://192.168.1.1:8000"], targets)
        self.assertEqual("Automated Hack-the-Box (HTB) CTF Solver", prompt_title)

    def test_extract_targets_and_prompt_title_pentest_agent(self):
        targets, prompt_title = asyncio.run(extract_targets_and_prompt_title(
            "Find all the vulns on 192.168.1.1 and 192.168.10.12", self.titles))
        self.assertEqual(["192.168.1.1", "192.168.10.12"], targets)
        self.assertEqual("Automated Penetration Tester", prompt_title)

    def test_extract_targets_and_prompt_title_pentest_assistant(self):
        targets, prompt_title = asyncio.run(extract_targets_and_prompt_title(
            "Help me find vulns on http://vulnerable.net", self.titles))
        self.assertEqual(["http://vulnerable.net"], targets)
        self.assertEqual("Bug Bounty Hunter Assistant", prompt_title)

    def test_specific_title(self):
        for title in self.titles:
            targets, prompt_title = asyncio.run(extract_targets_and_prompt_title(
                f"I am a \"{title.lower()}\". My target is http://vulnerable.net", self.titles))
            self.assertEqual(["http://vulnerable.net"], targets)
            self.assertEqual(title, prompt_title)
