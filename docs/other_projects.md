
# Similar projects

These are the similar projects I've looked at and my notes. My comments are based on my goals for this project. I could
be wrong or missing something important.

## https://github.com/aliasrobotics/cai

Few tools available. Primary tools is a generic linux command tool.

Appears to depend on proprietary alias0 model to get reasonable results.

- Commonly issues multiple nmap commands because the tools times out before the command finishes.
- Command progress isn't controlled causing large outputs overwhelming context or slowing command runtime.
- Other MCP tools aren't called over the generic linux command.
- Multiple-agent approach looks promising.
- Good support for many models.

I'd really like to get shyhurricane working with CAI to leverage the multi-agent support. I probably need to add an agent
that doesn't direct the model towards `generic_linux_command`.

## https://github.com/0x4m4/hexstrike-ai/tree/master

- Tools are exposed as individual MCP tools, so there are lots of tools.
- Lots of tools can easily overwhelm local model context sizes, precluding running locally on consumer hardware.
