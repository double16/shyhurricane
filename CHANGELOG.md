# shyhurricane Change Log

## Unreleased

### Features

- First release
- Migrate generator setup from deprecated `OpenAIGenerator`, `AmazonBedrockGenerator`, and `OllamaGenerator`
  to chat-based generators.

### Fixes

- Prevent persistent queue workers from racing to create queue directories during first-time initialization.

