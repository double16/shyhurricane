from typing import List, Optional

from mcp.server.fastmcp.prompts.base import Message, AssistantMessage, UserMessage

from shyhurricane.mcp_server import mcp_instance, get_server_context
from shyhurricane.prompts import ctf_agent_system_prompt, bug_bounty_agent_system_prompt, bug_bounty_chat_system_prompt, \
    pentester_agent_system_prompt, pentester_chat_system_prompt, htb_ctf_agent_system_prompt


open_world_disable_notes = "Network access has been disabled. Rely on indexed content."


@mcp_instance.prompt(title="Automated CTF Solver")
async def ctf_agent_prompt(target: str, query: Optional[str] = None) -> List[Message]:
    server_ctx = await get_server_context()
    messages: List[Message] = [AssistantMessage(ctf_agent_system_prompt)]
    if not server_ctx.open_world:
        messages.append(AssistantMessage(open_world_disable_notes))
    messages.append(UserMessage(query or f"Find the CTF flags on {target}."))
    return messages


@mcp_instance.prompt(title="Automated Hack-the-Box (HTB) CTF Solver")
async def htb_ctf_agent_prompt(target: str, query: Optional[str] = None) -> List[Message]:
    server_ctx = await get_server_context()
    messages: List[Message] = [AssistantMessage(htb_ctf_agent_system_prompt)]
    if not server_ctx.open_world:
        messages.append(AssistantMessage(open_world_disable_notes))
    messages.append(UserMessage(query or f"Find the CTF flags on {target}."))
    return messages


@mcp_instance.prompt(title="Automated Bug Bounty Hunter")
async def bug_bounty_agent_prompt(target: str, query: Optional[str] = None) -> List[Message]:
    server_ctx = await get_server_context()
    messages: List[Message] = [AssistantMessage(bug_bounty_agent_system_prompt)]
    if not server_ctx.open_world:
        messages.append(AssistantMessage(open_world_disable_notes))
    messages.append(UserMessage(query or f"Conduct a penetration test on {target}."))
    return messages


@mcp_instance.prompt(title="Bug Bounty Hunter Assistant")
async def bug_bounty_assistant_prompt(target: str, query: Optional[str] = None) -> List[Message]:
    server_ctx = await get_server_context()
    messages: List[Message] = [AssistantMessage(bug_bounty_chat_system_prompt)]
    if not server_ctx.open_world:
        messages.append(AssistantMessage(open_world_disable_notes))
    messages.append(UserMessage(query or f"Examine {target} for vulnerabilities."))
    return messages


@mcp_instance.prompt(title="Automated Penetration Tester")
async def pentest_agent_prompt(target: str, query: Optional[str] = None) -> List[Message]:
    server_ctx = await get_server_context()
    messages: List[Message] = [AssistantMessage(pentester_agent_system_prompt)]
    if not server_ctx.open_world:
        messages.append(AssistantMessage(open_world_disable_notes))
    messages.append(UserMessage(query or f"Conduct a penetration test on {target}."))
    return messages


@mcp_instance.prompt(title="Penetration Tester Assistant")
async def pentest_assistant_prompt(target: str, query: Optional[str] = None) -> List[Message]:
    server_ctx = await get_server_context()
    messages: List[Message] = [AssistantMessage(pentester_chat_system_prompt)]
    if not server_ctx.open_world:
        messages.append(AssistantMessage(open_world_disable_notes))
    messages.append(UserMessage(query or f"Examine {target} for vulnerabilities."))
    return messages


@mcp_instance.prompt(title="Penetration Test Auditor")
async def pentest_audit_prompt(target: str, query: Optional[str] = None) -> List[Message]:
    auditor_message = AssistantMessage("""
You are **Pentest Audit Bot**, an independent security auditor.  
Your job is to grade how thoroughly the test team examined the target **using only the documents stored in the retrieval system.**  
You **must not** collect new data from the internet or from the live target.

--- 

## Allowed actions:
--------------------
| Action           | Tool              | Purpose                                         |
| ---------------- | ----------------- | ----------------------------------------------- |
| Retrieve services covered | `find_netloc`     | Pull indexed hostname and ports in the form of hostname:port |
| Retrieve resources | `find_web_resources`     | Pull chunks that match a query (HTML, headers, scripts, logs). |

---

## Audit checklist:

Evaluate whether each phase below is present in the indexed evidence.  
Mark “✅ covered” or “❌ missing”.

1. **Recon / Enumeration** – ports, directories, tech stack, users  
2. **Vulnerability Analysis** – CVEs, OWASP Top-10, misconfigurations  
3. **Exploitation** – working PoCs, screenshots, shell output  
4. **Privilege Escalation** – local-root attempts, token theft  
5. **Post-Exploitation Loot** – DB dumps, secrets, sensitive files  

---

## Execution rules:
* Speak in concise **Markdown**.  
* Log progress in one-line notes such as  
  `website_rag("open ports") → 12 hits`  
* Iterate queries until all evidence is reviewed.  
* End the loop with **DONE** followed by the final report.

────────────────────────────────────────────────────────
Report template (Markdown to return after DONE)
────────────────────────────────────────────────────────
# Test-Coverage Report  (YYYY-MM-DD)

## Coverage Summary
| Phase | Status | Key Evidence |
|-------|--------|--------------|
| Recon | ✅ | [nmap.txt](…) |
| Exploitation | ❌ | – |

## Gaps & Recommended Tests
### {Short title}
- **Phase**: {e.g. Exploitation}
- **Why Needed**: {one-sentence rationale}
- **Suggested Technique**: {e.g. SQLi union-based test}
- **Reference**: [CVE-2023-1234](…), [OWASP A03](…)

DONE
""")
    server_ctx = await get_server_context()
    messages: List[Message] = [auditor_message]
    if not server_ctx.open_world:
        messages.append(AssistantMessage(open_world_disable_notes))
    messages.append(UserMessage(query or f"Examine {target} for test coverage."))
    return messages
