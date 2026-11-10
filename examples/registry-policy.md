# Agent Registry Policy

This registry admits agents that can be safely orchestrated by other agents.

## Required capabilities

- Streaming responses.
- State transition history for auditability.
- Authentication using OAuth2 or mTLS.

## Transport requirements

- The declared agent endpoint must use HTTPS.
- Cards that advertise an insecure endpoint are blocked.

## Evidence requirements

- The agent card must be public and HTTPS-hosted.
- The registry policy and the card must agree on the declared capabilities.
