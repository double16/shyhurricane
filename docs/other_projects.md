
# Similar projects

These are the similar projects I've looked at and my notes. My comments are based on my goals for this project. I could
be wrong or missing something important.

## MCP Servers

### https://github.com/0x4m4/hexstrike-ai/tree/master

- Tools are exposed as individual MCP tools, so there are lots of tools.
- Lots of tools can easily overwhelm local model context sizes, precluding running locally on consumer hardware.
- In similar fashion, tool arguments are tuned for use by the MCP.
- I could not see where timeouts and data size were managed. Not having indexed content makes this management difficult.

## Agentic Frameworks

shyhurricane is an MCP server designed to be used with other tools. An agentic framework that reasons about offensive
security is the primary use-case. Note that the assistant included in this repo is meant to help exercise the MCP server
and not intended to be in the same class as the following projects.

### https://github.com/aliasrobotics/cai

Few out-of-the-box tools available, which looks on purpose. The primary tool is a generic linux command tool.

- Commonly executes multiple `nmap` commands because the tools times out before the command finishes.
- Command progress isn't controlled causing large outputs overwhelming context or slowing command runtime.
- Multiple-agent approach looks promising.
- Good support for many models.

CAI looks like a good use case for shyhurricane.  I'd really like to get shyhurricane working with CAI to leverage the
multi-agent support.

### https://github.com/westonbrown/Cyber-AutoAgent

Cyber-AutoAgent looks good.
- Multiple agent
- Memory support
- Lots of work has gone into deployment scenarios.

MCP tool support is a planned feature.
