---
name: First Fonts — reviewed gateway request
about: Request the supported first Fonts image-build pipeline via the trusted-Host FIFO/SSM gateway
title: "[gateway] first Fonts"
labels: []
assignees: []
---

<!-- zog-gateway-request:v1 -->
```json
{
  "schema": 1,
  "workspace_id": "REPLACE_WITH_EXISTING_MANAGED_WORKSPACE_32_HEX",
  "operation": "build.submit",
  "parameters": {
    "lane": "REPLACE_WITH_EXISTING_MANAGED_LANE",
    "task": "graphics-fonts-image-v1",
    "selection": "REPLACE_WITH_EXISTING_ACCEPTED_GENERATION_64_HEX",
    "recipe_snapshot": "sha256:REPLACE_WITH_IMAGE_BUILD_RECIPE_SNAPSHOT_64_HEX"
  }
}
```
