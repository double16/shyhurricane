import asyncio
import inspect
import json
from typing import Dict, List

from haystack.dataclasses import ChatMessage
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations, PromptMessage, TextContent
from mcp.types import Prompt as MCPPrompt
from pydantic import BaseModel, Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.mcp_server.generator_config import get_generator_config


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Choose a prompt for offensive security operations",
        readOnlyHint=True,
        openWorldHint=False,
    )
)
async def prompt_chooser(ctx: Context, query: str) -> str:
    """
    Chooses the best prompt for an offensive security operation.

    Invoke this tool when the user requests an offensive security operation on a target and no instructions have been
    given concerning methodology, execution rules, or output format. The result of this tool should be taken as a system
    prompt or assistant instructions.

    Targets must be given in the form of a URL, host name, IP address, IP subnet or domain name.

    A specific prompt title may be given and will be something like "Penetration Tester Assistant". If an appropriate prompt cannot be found,
    this tool will return the list of available prompts.

    Examples:
        1. Find the CTF flags on 192.168.1.100
           Provides an agent prompt suitable for CTF challenges
        2. Find all the vulnerabilities on target.local
           Provides an agent prompt suitable for a penetration test
        3. Help me find the security flaws on 192.168.1.100
           Provides an assistant prompt suitable for a penetration test
        4. Help me find vulns on notarealsite.com
           Provides an assistant prompt suitable for a bug bounty program.
    """
    await log_tool_history(ctx, "prompt_chooser", query=query)

    titles: Dict[str, MCPPrompt] = dict()
    for mcp_prompt in await mcp_instance.list_prompts():
        titles[mcp_prompt.title] = mcp_prompt

    prompt = f"""
      You are a cybersecurity management expert.
      
      You determine the intent of a test and choose an appropriate agent or chat prompt based on the user query.
    
      You determine the target host name, IP address(es), site url(s) and ports the user is interested in. If the user specifies
      a scheme do not change it. Never suggest targets. Only accept explicit targets given by the user.
      
      Structure:
      Output the information as a valid JSON object. Only output the JSON. Do not include any other text except the JSON.
      
      The list of targets uses the key "targets". The value of "targets" is a valid JSON list. 

      The prompt is chosen from a fixed set of titles. The prompt title uses the key "title". The following are valid prompt titles:
      {", ".join(map(lambda t: '"' + t + '"', titles.keys()))}
      If the user is asking you to do something, prefer an agent or automated prompt. If the user is asking for help or
      research, prefer an assistant prompt.

      Your Task:
      """

    generator = get_generator_config().create_generator()
    sig = inspect.signature(generator.run)
    if "messages" in sig.parameters:
        prompt_messages = [
            ChatMessage.from_system(prompt),
            ChatMessage.from_user(query),
        ]
        generator_output = await asyncio.to_thread(generator.run, messages=prompt_messages)
    else:
        generator_output = await asyncio.to_thread(generator.run, prompt=prompt + "\n" + query)

    if "replies" in generator_output:
        replies = generator_output["replies"]
        if len(replies) > 0:
            reply = replies[0]
        else:
            reply = None
    else:
        reply = None

    targets = []
    prompt_title = None

    if reply:
        try:
            parsed = json.loads(reply)
            targets = parsed["targets"]
            prompt_title = parsed["title"]
        except json.decoder.JSONDecodeError:
            pass

    if not prompt_title or prompt_title not in titles:
        return f"Choose a prompt title from: {', '.join(titles.keys())}"

    if not targets:
        return f"At least one target is required. Specify as a host name, IP address, IP subnet, or URL."

    mcp_prompt = titles[prompt_title]
    messages = (await mcp_instance.get_prompt(name=mcp_prompt.name,
                                              arguments={"target": ', '.join(targets), "query": query})).messages

    text = []
    for msg in messages:
        if isinstance(msg.content, TextContent):
            text.append(msg.content.text)

    return "\n".join(text)


class PromptListResult(BaseModel):
    instructions: str = Field(description="Instructions for using the prompt titles")
    titles: List[str] = Field(description="List of available prompt titles")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Lists available prompt titles for offensive security operations",
        readOnlyHint=True,
        openWorldHint=False,
    )
)
async def prompt_list(ctx: Context) -> PromptListResult:
    """
    Provides a list of available prompt titles for offensive security operations.

    Invoke this tool when the user needs to give a prompt title in the query for the prompt_choose tool.
    """
    await log_tool_history(ctx, "prompt_list")
    titles = []
    for mcp_prompt in await mcp_instance.list_prompts():
        titles.append(mcp_prompt.title)
    return PromptListResult(
        instructions="Choose a prompt title and use it in the query for the prompt_chooser tool, along with the desired target(s)",
        titles=titles,
    )
