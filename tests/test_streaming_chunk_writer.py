import unittest

from haystack.dataclasses import StreamingChunk, ToolCall, ToolCallResult, ToolCallDelta

from shyhurricane.streaming_chunk_writer import StreamingChunkWriter


class StreamingChunkWriterTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.output = ""

        def printer(data: str):
            self.output += data

        self.callback = StreamingChunkWriter(printer=printer, verbose=False).callback

    def test_tool_call_stop_one(self):
        call_chunk = StreamingChunk(content='', index=0, tool_calls=[
            ToolCallDelta(index=0, tool_name='register_hostname_address',
                          arguments='{"address": "10.129.231.188", "host": "alert.htb"}', id=None)],
                                    tool_call_result=None, start=True, finish_reason='stop')
        self.callback(call_chunk)
        self.assertEqual("""🔄 register_hostname_address({"address": "10.129.231.188", "host": "alert.htb"})\n""",
                         self.output)

        result_chunk = StreamingChunk(
            content='', index=0, tool_calls=None,
            tool_call_result=ToolCallResult(result='',
                                            origin=ToolCall(
                                                tool_name='register_hostname_address',
                                                arguments={
                                                    'address': '10.129.231.188',
                                                    'host': 'alert.htb'},
                                                id=''),
                                            error=False),
            start=True, finish_reason=None)
        self.callback(result_chunk)
        self.assertEqual("""🔄 register_hostname_address({"address": "10.129.231.188", "host": "alert.htb"})
✅ register_hostname_address({"address": "10.129.231.188", "host": "alert.htb"})\n""", self.output)

    def test_tool_call_stop_one_error(self):
        call_chunk = StreamingChunk(content='', index=0, tool_calls=[
            ToolCallDelta(index=0, tool_name='register_hostname_address',
                          arguments='{"address": "10.129.231.188", "host": "alert.htb"}', id=None)],
                                    tool_call_result=None, start=True, finish_reason='stop')
        self.callback(call_chunk)
        result_chunk = StreamingChunk(
            content='', index=0, tool_calls=None,
            tool_call_result=ToolCallResult(result='',
                                            origin=ToolCall(
                                                tool_name='register_hostname_address',
                                                arguments={
                                                    'address': '10.129.231.188',
                                                    'host': 'alert.htb'},
                                                id=''),
                                            error=True),
            start=True, finish_reason=None)
        self.callback(result_chunk)
        self.assertEqual("""🔄 register_hostname_address({"address": "10.129.231.188", "host": "alert.htb"})
❌ register_hostname_address({"address": "10.129.231.188", "host": "alert.htb"})\n""", self.output)

    def test_tool_call_stop_three(self):
        call_chunk = StreamingChunk(content='', index=0, tool_calls=[
            ToolCallDelta(index=0, tool_name='register_hostname_address',
                          arguments='{"address": "10.129.231.188", "host": "alert.htb"}', id=None),
            ToolCallDelta(index=1, tool_name='register_hostname_address',
                          arguments='{"address": "10.129.231.188", "host": "statistics.alert.htb"}', id=None),
            ToolCallDelta(index=2, tool_name='port_scan',
                          arguments='{"timeout_seconds": 600, "ip_addresses": ["10.129.231.188"]}', id=None)],
                                    tool_call_result=None, start=True, finish_reason='stop')
        self.callback(call_chunk)
        self.assertEqual("""🔄 register_hostname_address({"address": "10.129.231.188", "host": "alert.htb"})
🔄 register_hostname_address({"address": "10.129.231.188", "host": "statistics.alert.htb"})
🔄 port_scan({"timeout_seconds": 600, "ip_addresses": ["10.129.231.188"]})
""", self.output)

        result_chunks = [
            StreamingChunk(
                content='', index=0, tool_calls=None,
                tool_call_result=ToolCallResult(result='',
                                                origin=ToolCall(
                                                    tool_name='register_hostname_address',
                                                    arguments={
                                                        'address': '10.129.231.188',
                                                        'host': 'alert.htb'},
                                                    id=''),
                                                error=False),
                start=True, finish_reason=None),
            StreamingChunk(
                content='', index=1, tool_calls=None,
                tool_call_result=ToolCallResult(result='',
                                                origin=ToolCall(
                                                    tool_name='register_hostname_address',
                                                    arguments={
                                                        'address': '10.129.231.188',
                                                        'host': 'statistics.alert.htb'},
                                                    id=''),
                                                error=False),
                start=True, finish_reason=None),
            StreamingChunk(
                content='', index=2, tool_calls=None,
                tool_call_result=ToolCallResult(result='',
                                                origin=ToolCall(
                                                    tool_name='port_scan',
                                                    arguments={
                                                        'timeout_seconds': 600,
                                                        'ip_addresses': [
                                                            '10.129.231.188']},
                                                    id=''),
                                                error=False),
                start=True, finish_reason=None)
        ]
        for chunk in result_chunks:
            self.callback(chunk)
        self.assertEqual("""🔄 register_hostname_address({"address": "10.129.231.188", "host": "alert.htb"})
🔄 register_hostname_address({"address": "10.129.231.188", "host": "statistics.alert.htb"})
🔄 port_scan({"timeout_seconds": 600, "ip_addresses": ["10.129.231.188"]})
✅ register_hostname_address({"address": "10.129.231.188", "host": "alert.htb"})
✅ register_hostname_address({"address": "10.129.231.188", "host": "statistics.alert.htb"})
✅ port_scan({"timeout_seconds": 600, "ip_addresses": ["10.129.231.188"]})
""", self.output)

    def test_tool_call_stream_one(self):
        call_chunks = [
            StreamingChunk(content='', index=0, tool_calls=[
                ToolCallDelta(index=0, tool_name='register_hostname_address', arguments=None,
                              id='call_1EJc1fSfzzxgBiLD99RmtRT2')], tool_call_result=None, start=True,
                           finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='{"', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='host', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='":"', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='statistics', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='.alert', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='.ht', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='b', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='","', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='address', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='":"', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='10', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='.', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='129', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='.', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='231', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='.', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='188', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=0,
                           tool_calls=[ToolCallDelta(index=0, tool_name=None, arguments='"}', id=None)],
                           tool_call_result=None, start=False, finish_reason=None),
            StreamingChunk(content='', index=None, tool_calls=None, tool_call_result=None, start=False,
                           finish_reason='tool_calls')
        ]
        for chunk in call_chunks:
            self.callback(chunk)
        self.assertEqual(
            """🔄 register_hostname_address({"host":"statistics.alert.htb","address":"10.129.231.188"})\n""",
            self.output)

        result_chunk = StreamingChunk(
            content='', index=0, tool_calls=None,
            tool_call_result=ToolCallResult(result='',
                                            origin=ToolCall(
                                                tool_name='query_findings',
                                                arguments={
                                                    'target': '10.129.231.188',
                                                    'limit': 100},
                                                id='call_HXrqfuvOo2LJ0FyhwQPU0Cwj'),
                                            error=False),
            start=True, finish_reason=None)
        self.callback(result_chunk)
        self.assertEqual("""🔄 register_hostname_address({"host":"statistics.alert.htb","address":"10.129.231.188"})
✅ register_hostname_address({"host":"statistics.alert.htb","address":"10.129.231.188"})
""", self.output)

    def test_content(self):
        chunk = StreamingChunk(
            content='I will begin by enumerating open ports and services on 10.129.231.188. I will also register the virtual hosts `alert.htb` and `statistics.alert.htb` with the',
            index=0, tool_calls=[], tool_call_result=None, start=True, finish_reason=None)
        self.callback(chunk)
        self.assertEqual(
            "I will begin by enumerating open ports and services on 10.129.231.188. I will also register the virtual hosts `alert.htb` and `statistics.alert.htb` with the",
            self.output)

    def test_newline_suppression(self):
        chunks = [
            StreamingChunk(content='I will begin by enumerating open ports and services on 10.129.231.188.', index=0,
                           tool_calls=[], tool_call_result=None, start=True, finish_reason=None),
            StreamingChunk(content='', index=0, tool_calls=[], tool_call_result=None, start=True, finish_reason=None),
            StreamingChunk(content='', index=0, tool_calls=[], tool_call_result=None, start=True, finish_reason="stop")
        ]
        for chunk in chunks:
            self.callback(chunk)
        self.assertEqual("I will begin by enumerating open ports and services on 10.129.231.188.\n", self.output)

    def test_content_tool_on_newline(self):
        chunks = [
            StreamingChunk(content='I will begin by enumerating open ports and services on 10.129.231.188.', index=0,
                           tool_calls=[], tool_call_result=None, start=True, finish_reason=None),
            StreamingChunk(content='', index=0, tool_calls=[
                ToolCallDelta(index=0, tool_name='port_scan',
                              arguments='{"timeout_seconds": 600, "ip_addresses": ["10.129.231.188"]}', id=None)],
                           tool_call_result=None, start=True, finish_reason='stop')
        ]
        for chunk in chunks:
            self.callback(chunk)
        self.assertEqual("""I will begin by enumerating open ports and services on 10.129.231.188.
🔄 port_scan({"timeout_seconds": 600, "ip_addresses": ["10.129.231.188"]})\n""", self.output)
