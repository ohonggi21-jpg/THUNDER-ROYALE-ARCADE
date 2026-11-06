# Cloudflare backend setup (free tier)

This folder is a staged backend migration. It does NOT switch the live game away from Firebase yet.

## Files
- `worker.js`: Cloudflare Worker API. Uses Firebase Anonymous Auth ID tokens for identity and a server-side `ADMIN_UIDS` secret for admin authorization.
- The administrator page includes a separate D1 backup-staging control; this does not change the live Firebase game data.
- `schema.sql`: D1 schema.
- `CLOUDFLARE_SETUP.md`: setup and safety notes.

## Configure the existing Worker
1. In Cloudflare, open the `thunder-royale-api` Worker → Settings → Variables and Secrets.
2. Add secrets:
   - `FIREBASE_PROJECT_ID` = `thunder-royale-arcade`
   - `ADMIN_UIDS` = the administrator Firebase Auth UID (comma-separated if more than one).
3. Open D1 database `thunder-royale-db` → Console and run the complete contents of `schema.sql`.
4. Open Worker → Edit code / Quick edit. Copy the contents of `worker.js` and replace the starter code, then Deploy.
5. Test `https://<your-worker-subdomain>.workers.dev/health`. It should return JSON with `"database":"connected"`.

## Importing the game backup
The live game still reads and writes Firebase. Do not switch it yet.
After the updated Worker is deployed and tested, use the administrator page in the game to select the downloaded JSON backup. The page sends it to the authenticated `POST /admin/importBackup` endpoint. The import is insert-only: it runs only when the D1 `players` table and `meta/season` row are empty. If either already contains data, the request is rejected without overwriting existing records. This creates a staged D1 copy only; the live game continues reading and writing Firebase until the later migration is completed.

## Current limitations
- This is phase 1: secure Worker foundation, D1 schema, backup import, and basic server-side admin actions.
- The browser game is not yet wired to this Worker. Its current Firebase reads/writes remain active.
- Score anti-cheat is not fully server-authoritative until every score/duel write path is migrated and Firestore client writes are restricted. Do not describe the current live game as cheat-proof.
- Automatic nickname moderation and full rollback UI are not yet wired to this Worker.
- Back up Firestore and keep the downloaded game JSON backup in a safe place before any migration.
- Never share Firebase UID allowlists, API tokens, or Cloudflare secrets publicly. Never commit secrets to GitHub.
- Stay on Cloudflare Workers Free and D1 Free; do not enable paid features or add a payment method.
