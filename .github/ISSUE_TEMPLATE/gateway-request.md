---
name: Zog execution gateway request
about: Submit a strictly validated host-deploy gateway request
title: "[gateway] "
labels: []
assignees: []
---

<!--
This template becomes active only after the gateway workflow is published on the
repository default branch. Do not add prose or additional code fences below.
The triggering GitHub actor must be authorized independently by repository policy.
-->
<!-- zog-gateway-request:v1 -->
```json
{
  "schema": 1,
  "request_id": "REPLACE_WITH_CANONICAL_32_HEX_UUID",
  "workspace_id": "REPLACE_WITH_EXISTING_HOST_DEPLOY_WORKSPACE_ID",
  "operation": "host.status",
  "parameters": {}
}
```
