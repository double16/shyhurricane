from typing import List, Optional, Annotated

from pydantic import BaseModel, Field
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from shyhurricane.mcp_server import mcp_instance, log_tool_history, get_server_context
from shyhurricane.mcp_server.encoder_decoder_impl import do_encode_decode


class EncoderDecoderResult(BaseModel):
    instructions: str = Field(description="Instructions for using the result")
    output: Optional[str] = Field(description="The result of applying the operations to the input")
    input: str = Field(description="Input to the tool")
    operations: List[str] = Field(description="Operations applied to the input to produce the output")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Encoder/Decoder",
        readOnlyHint=True,
        openWorldHint=False),
)
async def encoder_decoder(
        ctx: Context,
        operations: Annotated[
            List[str],
            Field(description="""
    List of operations from the following list. The values must only be from this list. Operations
    are applied in the order specified by sending the output of on operation into the next.
    Valid operations:
     - "base64_encode", base64 encodes the input_str
     - "base64_decode", base64 decodes the input_str
     - "to_hex", converts the input_str to a hexadecimal representation of the bytes, example: "the quick brown fox" becomes "74686520717569636b2062726f776e20666f78"
     - "from_hex", converts the input_str from a hexadecimal representation to bytes, example: "74686520717569636b2062726f776e20666f78" becomes "the quick brown fox"
     - "to_charcode", converts text to its unicode character code equivalent, example: "Γειά σου" becomes "039303b503b903ac002003c303bf03c5"
     - "from_charcode", converts text from its unicode character code equivalent, example: "039303b503b903ac002003c303bf03c5" becomes "Γειά σου"
     - "url_encode", encodes special characters required by a URL to percent-encoded hex, example: "the quick brown fox," becomes "the%20quick%20brown%20fox%2c"
     - "url_encode_all", encodes all characters to percent-encoded hex often required by URLs, example: "the quick brown fox," becomes "%74%68%65%20%71%75%69%63%6b%20%62%72%6f%77%6e%20"
     - "url_decode", decodes percent-encoded hex, example: "the%20quick%20brown%20fox%2c" becomes "the quick brown fox,"
     - "to_htmlentity", converts characters to HTML entities, example: "<img/>" becomes "&lt;img&sol;&gt;"
     - "from_htmlentity", converts HTML entities to characters, example: "&lt;img&sol;&gt;" becomes "<img/>"
     - "escape_unicode_backslash", converts characters to their unicode-escaped notations using a backslash, example: "σου" becomes "\u03C3\u03BF\u03C5"
     - "escape_unicode_percent", converts characters to their unicode-escaped notations using a percent, example: "σου" becomes "%u03C3%u03BF%u03C5"
     - "escape_unicode_u_plus", converts characters to their unicode-escaped notations using a backslash, example: "σου" becomes "U+03C3U+03BFU+03C5"
     - "unescape_unicode", converts characters from their unicode-escaped notations using a backslash, examples: "\u03C3%u03BFU+03C5" becomes "σου"
     - "to_uppercase", converts characters to their uppercase equivalent, example: "abc123" becomes "ABC123"
     - "to_lowercase", converts characters to their lowercase equivalent, example: "ABC123" becomes "abc123"
""")
        ],
        input_str: Annotated[str, Field(description="Input to be transformed")]
) -> EncoderDecoderResult:
    """
    Transforms the input_str by applying the operations in the specified order.

    Invoke this tool when the user needs to transform data from one form to another.
    """
    await log_tool_history(ctx, "encoder_decoder", input_str=input_str, operations=operations)

    try:
        output = do_encode_decode(input_str, operations)
    except ValueError as e:
        return EncoderDecoderResult(
            instructions=str(e),
            input=input_str,
            operations=operations,
            output=None,
        )

    await log_tool_history(ctx, "encoder_decoder: result", input=input_str, operations=operations, output=output)

    return EncoderDecoderResult(
        instructions="The output has been transformed as requested and is ready for use in the next task.",
        input=input_str,
        operations=operations,
        output=output,
    )
