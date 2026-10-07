# Veil Privacy Shield Rule for Antigravity Agents

This workspace is protected by the **Veil Enterprise AI Privacy Gateway**.

## Agent Instructions:
1. When generating, refactoring, or reviewing code or prompts containing potential secrets (API keys, tokens, passwords), customer PII (emails, phone numbers, SSNs, credit cards), or proprietary business data:
   - Call the `veil_inspect_prompt` tool to sanitize the payload before dispatching.
   - Respect fail-closed security blocks: If `veil_inspect_prompt` returns `action: "BLOCKED"`, halt exfiltration and alert the user.
2. To restore tokenized placeholders in final output, invoke `veil_restore_response`.
3. You can inspect gateway status anytime via `veil_get_status`.
