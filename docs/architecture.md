# architecture

The server is implemented in Python using asynchronous and multiprocess support. Most tools run asynchronously in the
server process. Long-running tools run in child processes and communicate with the server process using multiprocessing
queues or disk based queues.

# qdrant

The database is qdrant, a vector store and document store.

# file stores

The `${HOME}/.local/state/shyhurricane` directory holds other data needed by the server. Disk-based queues, logs, etc.
MCP servers are identified by their database path or URL. There is a directory named by the URL to prevent files being
overwritten.

Files worth pointing out that may be useful to the user:
- `logs/index.txt` holds all indexed katana JSON so that it may re-indexed later
- `logs/finding.jsonl` holds all saved findings because there isn't a great way for users to see them

# haystack-ai

Haystack-AI is used for LLM and embedding code. It provides a good abstraction layer.

# katana JSONL

`katana` is a popular command line spidering tool. It outputs full request/response data as [JSONL](https://jsonltools.com/what-is-jsonl). 

shyhurricane makes use of Katana's JSONL format extensively. Most data that is meant to be indexed is converted to it.

# Docker

The `ghcr.io/double16/shyhurricane_unix_command:main` container is used to provide command isolation from the host
system and a consistent tool environment.

## volume mcp_session

The `mcp_session` volume is used to store files for MCP sessions across command invocations. It is mounted to the
`/work` path. Each session has a unique ID and a directory created inside `/work`. There are no attempts made to
isolate command calls to their own files other than obscurity.

`/tmp` and `/var/tmp` are commonly used by the LLMs to save files. Instructions do not seem to deter them. Therefore
these directories contents are synced before and after a command starts. Various attempts at docker mounts were
tried and failed for various reasons.

## volume seclists

The SecLists repository contains popular word lists. The repo is large and is not included with the docker image.
Instead, the `seclists` volume is created and populated by the server.

## mitm_proxy

Commands that are intended to capture HTTP requests and index use `mitm_proxy` to capture and output the request/response
into katana JSON. The `mitm_to_katana.py` script is a plugin for `mitm_proxy` to accomplish this. The spider and
directory busting tools use the proxy in the container command.

# background process

Some tools are expected to use enough resources to run in a separate python process. The tools are:

- `port_scan` (long-running, network bound)
- `spider_website` (long-running, network bound)
- `directory_buster` (long-running, network bound)
- `save_finding` (GPU/memory use)

The code is in the `shyhurricane/task_queue` directory. The request is added to a task queue and one of the workers
will pull from the queue and execute the tool.

The number of workers is defined by the `--task-pool-size` argument. It defaults to 3 and can be increased without
severe performance penalities.

# content index process

Context indexing means the data collected (HTTP request/response, nmap results, etc.) is vectorized using an embedding
model and stored in the database. Each type of data has its own collection with the ability to use an embedding
model specific to that content.

The intention is to later query for data that has similarities to known (vulnerable) patterns. A classic example is finding
all data where the javascript `eval()` function is invoked. However, a vector database is more powerful than that. More
complex patterns such as multiple javascript statements, HTML form patterns, etc. can be matched. After retrival the LLM
can reason about the data to determine vulnerabilities.

Each type of data may have multiple token lengths to account for different query scenarios. Longer lengths provide better
matching of long contextual searches. Short lengths are better for code snippets, such as the `eval()` example given.

Data is stored according to `shyhurricane/doc_type_model_map.py`. A document may be included in more than one collection.
The `content` collection is special, it receives all HTTP request/response data regardless of type. 

There are two levels of indexing separated by resource consumption. Generating embeddings is expensive in GPU, memory and compute.

The first level is storing the raw data using a single embedding vector. The collections considered here are `content`
and `network`. Several tool expect the raw data to be in `content` as a form of caching. This indexing is always done.

The second level is normalization and creating multiple vectors. Smaller token lengths will cause the data to be
split, with some overlap, and vectorized. A single-page app javascript file can easily have thousands of parts that are
vectorized and stored.

Normalization is done based on content type before vectorized. Javascript is deobfuscated and formatted. HTML, CSS and JSON
are formatted. This helps make vectors diverge unnecessarily.

Code for the indexing processes is in `shyhurricane/index`. There is always and only one first-level index process. The
"doc type" index is resource intensive and can have multiple processes. On a single consumer machine, like a laptop, more
than one process is not practical. The doc type index will not be started in "low-power" mode, a mode specified by the
user with an option.

Data to be indexed is stored in SQLite based persistent queues. Restarting the MCP server will cause no loss of data. In
low-power mode, the doc type queue is still populated. Restarting the server without the low power option will cause the
data to be processed using the more expensive "doc type" indexing.

## querying

The `find_web_resources` performs the queries. The input to this tool is a query from an LLM. It could be a full sentence
or keyword(s) such as "IDOR" or "XSS". The LLM is used to extract vulnerability types from the query and produce
snippets to be vectorized and sent to the database.

Since there are known vulnerability classes, and known vulnerable patterns for those classes, some patterns are statically
defined in this repo. See the `shyhurricane/assets/query` directory. In addition to the static patterns, the LLM is used
to add additional patterns with creativity.

# proxy server

Since data is cached, it can be useful to re-process the data with other tools. An HTTP proxy is included with the server
to allow this. It will only return indexed data. Missing data will result in a page that lists recommended URLs to visit.
Any tools that do link discovery are expected to use this list to continue processing.

The proxy server has CA certificate generation. The `/status` endpoint include the CA certificate.

# channels

Channels are used to keep persistent TCP connections open. Connections are kept in the server process memory.

Reverse channels attempt to find the correct network interface for the target IP address. The purpose is to bind to
a VPN IP address, if one is used.
