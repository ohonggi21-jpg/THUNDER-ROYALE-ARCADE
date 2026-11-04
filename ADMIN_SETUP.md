# THUNDER ROYALE ARCADE · Admin & moderation backend

## What this adds
- Cloud Functions callable admin operations (delete account, suspend/unsuspend, adjust scores, restore a saved player snapshot, set the season number).
- Server-side nickname and score-activity moderation trigger.
- Append-only admin audit records in `admin_audit`.
- Admin authorization by Firebase Authentication UID allowlist. There is no client-side admin PIN.

## One-time Firebase setup
1. Use a Firebase project on the Blaze (pay-as-you-go) plan; Cloud Functions deployment may require billing to be enabled. Install Firebase CLI and sign in with the Firebase project owner account.
2. In Firebase Console → Authentication → Sign-in method, keep Anonymous enabled (the game currently uses anonymous auth).
3. Open the game on the device that should administer it. Tap the THUNDER ROYALE title/logo five times to open the hidden admin panel. The panel displays that device's Firebase Auth UID; login is not required.
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
6. Reload the game. Open the hidden admin panel and press **서버 관리자 인증**. Until `claimPlayer` is deployed, the page permits a clearly labeled temporary legacy login; automated moderation and secure admin actions are not active during that interim.
7. Player profiles are claimed by the current anonymous Firebase UID on first login. This means a nickname is tied to that browser/device identity; anonymous sign-in does not provide cross-device account recovery. A banned UID is blocked from creating another nickname on the same Firebase identity.

## Important security notes
- Admin callable actions always verify the caller UID against `ADMIN_UIDS` on the server. Hiding the admin UI is not the security boundary.
- The moderation trigger automatically blocks accounts whose nickname matches the configured blocked-term list, or whose recent score log shows a high-rate/invalid-score pattern. Review false positives in the admin panel and lift the restriction if appropriate.
- The current game still contains legacy client-side player/duel writes. The moderation trigger detects invalid score ranges and unusually rapid score-log activity, but a determined user may still alter plausible values through legacy client writes. For full anti-cheat protection, Firestore rules and all game-result submission paths must be migrated to server-authoritative writes before claiming scores are tamper-proof. This implementation must not be described as cheat-proof.
- The hidden admin panel is server-authorized by UID allowlist. Never publish `functions/.env`; `.gitignore` excludes it.
- Automatic language filtering applies to player nicknames. This game has no public chat feature, so there is no chat-message moderation path yet.
- Existing Firestore data is not reset by deployment. Existing unclaimed nicknames are claimed by the first device that signs in with that nickname after deployment; review legacy accounts before public rollout.
- Back up the Firestore database before production rollout.
