<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 PrintForge Contributors -->

# PrintForge Air-Gap Bundle (Hauler)

This directory contains [Hauler](https://rancherfederal.github.io/hauler-docs/)
manifests for building a fully self-contained OCI artifact bundle that can be
transferred to SIPR (or any air-gapped) enclaves on approved removable media.

## Contents

| File | Purpose |
|---|---|
| `hauler-manifest.yaml` | Container images (application + infrastructure) |
| `hauler-charts.yaml` | Helm charts |

## Prerequisites

Install the following tools on a **NIPR build workstation** with network access:

- **Hauler CLI** v1.x or later (`hauler version`)
- **Docker** or a compatible container runtime (for pulling images)
- **Helm** v3.x (for chart packaging)
- **Approved removable media** for cross-domain transfer per local ISSM guidance

## Building the Bundle

All commands are run from the repository root.

### 1. Sync images and charts into the local Hauler store

```bash
hauler store sync \
  --files deploy/hauler/hauler-manifest.yaml \
  --files deploy/hauler/hauler-charts.yaml
```

This pulls every image listed in `hauler-manifest.yaml` and packages the Helm
chart from `deploy/helm/printforge`.

### 2. Verify store contents

```bash
hauler store info
```

Confirm that all images and the chart appear in the output.

### 3. Save the store to a portable archive

```bash
hauler store save --filename printforge-airgap-0.1.0.tar.zst
```

The resulting `printforge-airgap-0.1.0.tar.zst` is a single compressed archive
containing every OCI artifact needed for a complete deployment.

### 4. Generate checksums

```bash
sha256sum printforge-airgap-0.1.0.tar.zst > printforge-airgap-0.1.0.tar.zst.sha256
```

## Transferring to SIPR

1. Copy `printforge-airgap-0.1.0.tar.zst` and its `.sha256` file to approved
   removable media following your installation's cross-domain transfer procedures.
2. Have the transfer reviewed and approved by the local ISSM/ISSO.
3. Transport the media to the SIPR enclave.

## Loading on SIPR

On the SIPR deployment host (RKE2 central or K3s edge node):

### 1. Verify archive integrity

```bash
sha256sum -c printforge-airgap-0.1.0.tar.zst.sha256
```

### 2. Load the Hauler store from the archive

```bash
hauler store load --filename printforge-airgap-0.1.0.tar.zst
```

### 3. Start the embedded OCI registry

```bash
hauler store serve registry --port 5000
```

This starts a local OCI-compliant registry on port 5000 that serves all images
and charts from the loaded store. Leave this running (or configure it as a
systemd service) for the duration of the deployment.

### 4. (Optional) Copy images into an existing registry

If the enclave already has a registry (e.g., Harbor), push images there instead:

```bash
hauler store copy registry://registry.sipr.printforge.mil
```

## Deploying with Helm

Point Helm at the local Hauler registry (or existing enclave registry) and
override the image registry in values:

```bash
# Using the local Hauler registry on localhost:5000
helm install printforge \
  oci://localhost:5000/hauler/printforge \
  --version 0.1.0 \
  --namespace printforge \
  --create-namespace \
  --set global.image.registry=localhost:5000 \
  --set global.image.pullPolicy=IfNotPresent \
  --set postgresql.auth.existingSecret=printforge-db-secret \
  --set rustfs.existingSecret=printforge-rustfs-secret \
  --set tls.existingSecret=printforge-tls-secret
```

For edge (K3s) cache-node deployments, install with the cache-node profile:

```bash
helm install printforge-edge \
  oci://localhost:5000/hauler/printforge \
  --version 0.1.0 \
  --namespace printforge \
  --create-namespace \
  --set global.image.registry=localhost:5000 \
  --set cacheNode.enabled=true \
  --set apiGateway.replicas=0 \
  --set driverService.replicas=0
```

## Updating the Bundle

When a new version is released:

1. Update image tags in `hauler-manifest.yaml`
2. Update the chart version in `hauler-charts.yaml`
3. Repeat the build, transfer, and load steps above

## Troubleshooting

| Symptom | Resolution |
|---|---|
| `hauler store sync` fails to pull an image | Verify Docker is running and the image exists in the source registry |
| SHA-256 mismatch after transfer | Re-copy the archive; media may have corruption |
| `ImagePullBackOff` in Kubernetes | Confirm `global.image.registry` points to the Hauler registry and the registry is running |
| Chart not found in OCI registry | Run `hauler store info` to confirm the chart was included in the bundle |
