# Agent Card Conformance Gate

A reusable GenLayer Intelligent Contract for evidence-backed agent registry
admission. A publisher registers an A2A-style agent card, a registry policy, a
required capability mask, and whether authentication is mandatory. Anyone can
trigger an assessment.

GenLayer validators independently fetch the card and the policy, extract the
claimed capabilities, authentication scheme, and transport security, and
compare the decision-bearing fields. Deterministic contract code then returns
`APPROVED`, `CONDITIONAL`, `BLOCKED`, or `REVIEW_REQUIRED`.

## Decision policy

| Condition | Decision |
| --- | --- |
| Sources conflict or required facts are missing | `REVIEW_REQUIRED` |
| The declared endpoint is not HTTPS | `BLOCKED` |
| Authentication is required but absent | `BLOCKED` |
| A required capability is missing | `CONDITIONAL` |
| Every required capability is present | `APPROVED` |

## Capability bits

| Bit | Capability |
| --- | --- |
| 1 | streaming |
| 2 | push notifications |
| 4 | state transition history |
| 8 | authentication |
| 15 | all capabilities |

## Contract interface

| Method | Type | Purpose |
| --- | --- | --- |
| `register_agent(agent_id, agent_card_url, policy_url, required_capabilities, require_auth)` | write | Register an agent and its policy |
| `assess(agent_id)` | write | Fetch both sources through validator consensus |
| `withdraw(agent_id)` | write | Publisher-only withdrawal |
| `is_conformant(agent_id)` | view | Boolean admission signal for other contracts |
| `get_assessment(agent_id)` | view | Full public assessment record |
| `capability_bits()` | view | Expose the fixed capability and decision codes |

## Why GenLayer

Agent cards are live, unstructured public evidence. A registry cannot rely on a
static allowlist or a private off-chain review service if other contracts need
to consume the result. This gate makes the evidence, the extraction, the
validator comparison, and the final policy decision public and reproducible.

## Local verification

```shell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
genvm-lint check contracts/agent_card_gate.py
pytest tests/direct/ -q
```

## License

MIT
