# CommandLayer Runtime (Commons)

Reference runtime for CommandLayer Commons verbs.

## Endpoints
- GET /health
- GET /debug/env
- POST /fetch/v1.0.0
- POST /verify

## Example
RECEIPT=$(curl -s -X POST https://<YOUR_DOMAIN>/fetch/v1.0.0 \
  -H "Content-Type: application/json" \
  -d '{"x402":{"entry":"x402://fetchagent.eth/fetch/v1.0.0","verb":"fetch","version":"1.0.0"},"source":"https://example.com"}')

printf '%s' "$RECEIPT" | curl -s -X POST "https://<YOUR_DOMAIN>/verify?ens=1" \
  -H "Content-Type: application/json" -d @-
