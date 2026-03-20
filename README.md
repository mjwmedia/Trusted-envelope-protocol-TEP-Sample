# Trusted Envelope Protocol (TEP)

**Cryptographic input provenance for LLM agents.**

TEP is a protocol for labeling message provenance in AI agent systems. By cryptographically signing user commands at the gateway, agents can distinguish authenticated instructions from external content — enabling trust-aware policy enforcement as a defense layer against prompt injection.

## The Problem

When an AI agent fetches external content (webpages, documents, emails), that content enters the same context window as user commands. The agent cannot structurally distinguish between legitimate instructions and injected attacks.

## The Solution

TEP provides:

- **HMAC-SHA256 signed envelopes** for authenticated user commands
- **Trust-level labeling** (authenticated, external, derived, etc.)
- **Policy enforcement** that restricts dangerous tools when untrusted content is present

The gateway signs user messages cryptographically. External content is labeled but unsigned. Policy engines can then block sensitive actions (exec, send, write) when the context contains untrusted content.

## Interactive Simulator

This repository contains an interactive demo that shows TEP in action:

1. **TEP Enabled:** Malicious instructions in external content are blocked by the policy engine
2. **TEP Disabled:** The agent executes injected commands without restriction

### Run Locally

**Prerequisites:** Node.js

```bash
npm install
npm run dev
```

Open [http://localhost:5173](https://trusted-envelope-protocol-tep-sample-production.up.railway.app/#) to see the simulator.

## How It Works

```
User Command                     External Content
     │                                  │
     ▼                                  ▼
┌─────────────────┐            ┌─────────────────┐
│ Gateway signs   │            │ No signature    │
│ with HMAC-SHA256│            │ Tagged external │
└────────┬────────┘            └────────┬────────┘
         │                              │
         ▼                              ▼
    trust_level:                  trust_level:
    authenticated                  external
         │                              │
         └──────────┬───────────────────┘
                    ▼
            ┌───────────────┐
            │ Policy Engine │
            │ Checks trust  │
            │ before tools  │
            └───────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   [Allowed]               [Blocked]
   Summarize              exec, send,
   read, search           write files
```

## Trust Levels

| Level | Description | Cryptographic Status |
|-------|-------------|---------------------|
| `authenticated` | HMAC-signed user command | Cryptographically verified |
| `system` | Gateway-generated content | Implicitly trusted |
| `tool_output` | Output from tool execution | Tagged by gateway |
| `external` | Fetched external content | Tagged, unsigned |
| `derived` | Model output based on other content | Inherits lowest trust |

## What TEP Does NOT Do

TEP is one layer in defense-in-depth, not a complete solution:

- Does not make external content inert — the model still processes it
- Does not guarantee model compliance with trust labels
- Does not protect against compromised gateways or malicious plugins
- Requires companion policy enforcement to be effective

## Specification

The full technical specification is available in the [TEP Spec Document](docs/trusted-envelope-spec.md).

## Author

**Matt Weitzman**  
- [LinkedIn](https://linkedin.com/in/mattweitzman)
- [Swarm Digital Marketing](https://swarmdigital.io)

## License

Apache-2.0

---

*TEP is a proposed protocol for improving AI agent security. Feedback and contributions welcome.*
