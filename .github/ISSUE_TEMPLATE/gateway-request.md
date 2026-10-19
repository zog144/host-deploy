---
name: Zog execution gateway request
about: Submit a strictly validated host-deploy gateway request
title: "[gateway] "
labels: []
assignees: []
---

<!-- zog-gateway-request:v1 -->
```json
{
  "schema": 1,
  "request_id": "REPLACE_WITH_CANONICAL_32_HEX_UUID",
  "workspace_id": "REPLACE_WITH_EXISTING_HOST_DEPLOY_WORKSPACE_ID",
  "operation": "build.status",
  "parameters": {
    "lane": "REPLACE_WITH_APPROVED_READONLY_LANE",
    "pipeline_id": "REPLACE_WITH_EXISTING_PIPELINE_ID"
  }
}
```
