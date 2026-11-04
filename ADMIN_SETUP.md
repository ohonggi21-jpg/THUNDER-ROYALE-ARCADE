# THUNDER ROYALE ARCADE · Admin & moderation backend

## What this adds
- Cloud Functions callable admin operations (delete account, suspend/unsuspend, adjust scores, restore a saved player snapshot, set the season number).
- Server-side nickname and score-activity moderation trigger.
- Append-only admin audit records in `admin_audit`.
- Admin authorization by Firebase Authentication UID allowlist. There is no client-side admin PIN.

## One-time Firebase setup
1. Install Firebase CLI and sign in with the Firebase project owner account.
2. In Firebase Console → Authentication → Sign-in method, keep Anonymous enabled (the game currently uses anonymous auth).
3. Open the game once on the device that should administer the game. The hidden admin panel displays that device's current Firebase Auth UID.
4. Copy that UID. In the repository's `functions` folder create a local `.env` file (do not commit it):
   ```
   ADMIN_UIDS=PASTE_ADMIN_UID_HERE
   ```
   Multiple administrators can be comma-separated.
5. Deploy:
   ```bash
   cd functions && npm install && cd ..
   firebase deploy --only functions
   ```
6. Reload the game. Open the hidden admin panel and press **서버 관리자 인증**.

## Important security notes
- Admin callable actions always verify the caller UID against `ADMIN_UIDS` on the server. Hiding the admin UI is not the security boundary.
- The moderation trigger automatically blocks accounts whose nickname matches the configured blocked-term list, or whose recent score log shows a high-rate/invalid-score pattern. Review false positives in the admin panel and lift the restriction if appropriate.
- The current game still contains legacy client-side player/duel writes. For full anti-cheat protection, the Firestore rules and game-result submission flow must be migrated to server-authoritative writes before claiming scores are tamper-proof. This backend is not a replacement for that migration.
- Existing Firestore data is not migrated or reset by deployment.
- Back up the Firestore database before production rollout.
