# Portal submission draft

## Category

Builder -> Intelligent Contract

## Description (English, under 1,000 characters)

Agent Card Conformance Gate is a reusable GenLayer primitive for evidence-backed agent registry admission. A publisher registers an A2A-style agent card, a registry policy, a required capability mask, and whether authentication is mandatory. Anyone can trigger an assessment. Validators independently fetch the card and policy; an LLM extracts only the declared capabilities, authentication scheme, transport security, and source consistency. Deterministic contract code blocks insecure endpoints and missing authentication, marks incomplete capability coverage as conditional, and approves a fully conformant card. Other contracts can consume `is_conformant(agent_id)`. The repository includes source, tests, deployment instructions, and a live example for agent marketplaces, registries, and orchestration systems.

## Live evidence

- Public source repository: https://github.com/Fan-Yu0/genlayer-agent-card-gate
- Agent card: https://raw.githubusercontent.com/Fan-Yu0/genlayer-agent-card-gate/main/examples/agent-card.json
- Registry policy: https://raw.githubusercontent.com/Fan-Yu0/genlayer-agent-card-gate/main/examples/registry-policy.md
- Contract: `TBD`
- Deployment transaction: `TBD`
- Assessment transaction: `TBD`

## First live example

```text
agent_id: triage-agent
agent_card_url: https://raw.githubusercontent.com/Fan-Yu0/genlayer-agent-card-gate/main/examples/agent-card.json
policy_url: https://raw.githubusercontent.com/Fan-Yu0/genlayer-agent-card-gate/main/examples/registry-policy.md
required_capabilities: 13
require_auth: true
```

Then call `assess("triage-agent")`.

## Reviewer checklist

- Persistent state and a clear lifecycle.
- Publisher-only registration and withdrawal.
- Permissionless evidence refresh.
- Validator independently re-fetches both sources.
- The LLM extracts only constrained evidence.
- The final decision is deterministic.
- Missing or conflicting evidence fails closed.
- Source, tests, documentation, and deployment instructions are public.
