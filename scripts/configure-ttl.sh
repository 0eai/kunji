#!/usr/bin/env bash
# Configure Firestore TTL policies for kunji's time-bound collections (project kunji-cc).
#
# Firestore deletes a doc some time after the timestamp in its TTL field passes. kunji's relay/session docs
# already WRITE a `ttl` (a Firestore Timestamp) or `expiresAt` field — but the TTL *policy* is an out-of-band
# gcloud step (not in firebase.json), so it must be applied once per project. Run this after the first deploy
# and any time a new time-bound collection is added. Safe to re-run (idempotent).
#
# TTL needs a Firestore *Timestamp* field. Collections whose only time field is a plain number (linkSessions
# `expiresAt`, the rate-limit buckets, revocations) are NOT TTL-able — the scheduled sweep (issuerCleanup) is
# their cleanup path instead. See docs/ops-cost-controls.md + issuer-functions/opsClean.js.
#
# Usage:  ./scripts/configure-ttl.sh            # apply to kunji-cc
#         PROJECT=other ./scripts/configure-ttl.sh
set -euo pipefail
PROJECT="${PROJECT:-kunji-cc}"
DB="${DB:-(default)}"

# (field, collection-group) pairs whose docs carry a Firestore Timestamp TTL field.
enable() {
  local field="$1" group="$2"
  echo "→ TTL on $group.$field"
  gcloud firestore fields ttls update "$field" \
    --collection-group="$group" \
    --project="$PROJECT" \
    --database="$DB" \
    --enable-ttl \
    --async
}

# `ttl` Timestamp field — the app + issuer relay/session collections.
for group in agentSessions agentRequests credentialSessions pushChannels \
             issuerOffers issuerTokens issuerLoginSessions issuerSessions \
             verificationSessions opsDaily; do
  enable ttl "$group"
done

# `expiresAt` Timestamp field — the per-vault activity log (a collection group under vaults/{id}/activity).
enable expiresAt activity

echo
echo "Submitted. TTL policy builds can take a few minutes; verify with:"
echo "  gcloud firestore fields ttls list --project=$PROJECT --database='$DB'"
