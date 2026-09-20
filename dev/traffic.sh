msg() { curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8417/v1/messages -H "x-api-key: sk-local-test" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -d "$1"; }
TOOLS='"tools":[{"name":"get_weather","description":"查询天气","input_schema":{"type":"object","properties":{"city":{"type":"string"}}}}]'
for i in 1 2; do msg '{"model":"claude-sonnet-4-5","max_tokens":2048,"stream":true,"system":"你是一个简洁的助手。","thinking":{"type":"enabled","budget_tokens":1024},'"$TOOLS"',"messages":[{"role":"user","content":"weather in Shanghai '$i'?"}]}'; done
for i in 3 4; do msg '{"model":"claude-sonnet-4-5","max_tokens":512,"stream":true,"system":"你是一个简洁的助手。","messages":[{"role":"user","content":"你好 '$i'"}]}'; done
for i in 1 2 3 4; do msg '{"model":"gpt-5-mini","max_tokens":256,"stream":true,"messages":[{"role":"user","content":"跨协议 '$i'"}]}'; done
msg '{"model":"claude-sonnet-4-5","max_tokens":2048,"stream":true,"system":"你是一个简洁的助手。",'"$TOOLS"',"messages":[{"role":"user","content":"weather again? 顺便记一下库连接串 postgres://app:S3cretPassw0rd@db.prod.example.com:5432/main"},{"role":"assistant","content":[{"type":"text","text":"好的，我来查询。"},{"type":"tool_use","id":"toolu_prev","name":"get_weather","input":{"city":"Beijing"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_prev","content":"晴，26°C"}]}]}'
msg '{"model":"claude-sonnet-4-5","max_tokens":512,"stream":true,"system":"你是一个简洁的助手。","messages":[{"role":"user","content":"再来一次"}]}'
msg '{"model":"claude-opus-4-1","max_tokens":512,"stream":true,'"$TOOLS"',"messages":[{"role":"user","content":"帮我初始化项目"}]}'
msg '{"model":"claude-haiku-4-5","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}]}'
msg '{"model":"gpt-5-mini","max_tokens":256,"stream":true,"messages":[{"role":"user","content":"跨协议 5"}]}'
# Responses 协议（Codex 形态）：同样的请求分别发往原样转发与会改写请求的渠道
resp() { curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:8417/v1/responses -H "Authorization: Bearer sk-local-test" -H "content-type: application/json" -d "$1"; }
CODEX='"stream":true,"store":false,"parallel_tool_calls":false,"reasoning":{"effort":"medium"},"text":{"verbosity":"high"},"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"namespace","name":"functions","description":"d","tools":[{"type":"custom","name":"exec"}]}]},{"type":"message","role":"developer","content":[{"type":"input_text","text":"You are Codex, an agent based on GPT-6. Collaborate with the user until the goal is handled."}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]'
resp '{"model":"gpt-6-astra",'"$CODEX"'}'
resp '{"model":"gpt-6-luna",'"$CODEX"'}'
echo
