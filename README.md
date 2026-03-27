# OpenClaw SovereignShield Plugin

A native, deterministic security defense layer for the **OpenClaw** autonomous AI agent framework.

By design, OpenClaw agents have autonomous access to extremely sensitive system tools (such as `bash`, `exec`, `python`, and `fs_write`). This unprecedented level of environment access makes standalone AI agents critically vulnerable to **Prompt Injections**, where a malicious user overrides the logic to spawn reverse shells or destroy files. 

**This plugin acts as an explicit, high-speed security interception layer.** It intercepts every high-risk OS execution call *before* it touches your host machine, routing the payload through **SovereignShield** - an industrialized LLM sandbox and firewall - to prevent Remote Code Execution (RCE) patterns in sub-milliseconds.

---

## 🔒 Architecture & How It Works

This integration leverages the exact OpenClaw Gateway `before_tool_call` plugin hook. 
Before an autonomous agent executes a sensitive capability like `bash`, the OpenClaw execution loop is temporarily paused. The raw execution arguments are extracted and rapidly audited by the SovereignShield engine. 

- **Deterministic 0-day Blocking:** Halts known reverse shells, curl-bash attacks, and malicious payloads using advanced systemic pattern matching (without network latency). 
- **Fail-Closed Design:** If the security layer detects a payload as compromised, or if the underlying daemon crashes, the execution natively aborts via `{ block: true }` and OpenClaw alerts the user. 
- **Absolute Portability:** You are in absolute control of how the security runs. Run it privately on your own hardware (`Local Daemon`) or fully-managed over HTTPS (`Cloud SaaS`).

---

## 🚀 Installation & Configuration

Install the plugin securely into your OpenClaw environment:
```bash
openclaw plugins install github.com/mattijsmoens/openclaw-sovereign-shield
```

### 1. Local Daemon Mode (Default)
By default, the plugin connects to `http://localhost:8765`.
For maximum privacy and zero latency, run the SovereignShield daemon locally on your machine.

```bash
pip install sovereign-shield
sovereign-shield-daemon
```
*Note: To run pure deterministic checks, you need zero keys. If you want Advanced Semantics (VetoShield), export `VETO_PROVIDER=gemini` and `GEMINI_API_KEY` before starting the daemon!*

### 2. Cloud SaaS Mode (Fully Managed)
If you don't want to run the python daemon, shift the entire security layer to the SovereignShield Managed Cloud.
Export your API key before booting your OpenClaw agent instance. The Node.js plugin will automatically detect the key and switch routing to the HTTPS SaaS endpoint.
```bash
export SOVEREIGN_SHIELD_API_KEY="your_api_key_here"
export SOVEREIGN_SHIELD_MODE="remote"
```

---

## ⚙️ Customization

By default, the plugin protects a strict list of vectors: `bash`, `system.run`, `fs_write`, `fs_read`, `python`, `exec`.

If your agent uses different native tools or you want to expand coverage, you can directly override the hook targets via bash environment without ever altering the JavaScript binary.

```bash
# Example: Only heavily sandbox terminal tools
export SS_PROTECTED_TOOLS="bash,python,terminal"
```

---

*Securing the Autonomous AI Era, locally and permanently.*
