const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { onDocumentWritten } = require("firebase-functions/v2/firestore");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

const ADMIN_UIDS = new Set(
  String(process.env.ADMIN_UIDS || "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean)
);

// Keep this list short and maintainable. Add project-specific terms only after review.
const BLOCKED_NAME_TERMS = [
  "시발", "씨발", "ㅅㅂ", "병신", "븅신", "개새끼", "좆", "ㅈㄴ",
  "fuck", "shit", "bitch", "nigger"
];

function requireAuth(request) {
  if (!request.auth) throw new HttpsError("unauthenticated", "로그인이 필요합니다.");
  return request.auth.uid;
}
function requireAdmin(request) {
  const uid = requireAuth(request);
  if (!ADMIN_UIDS.has(uid)) {
    throw new HttpsError("permission-denied", "관리자 권한이 없습니다. Firebase ADMIN_UIDS 설정을 확인하세요.");
  }
  return uid;
}
function cleanReason(value) {
  return String(value || "").trim().slice(0, 240);
}
function playerRef(id) {
  if (typeof id !== "string" || !/^[a-z0-9_]{1,180}$/.test(id)) {
    throw new HttpsError("invalid-argument", "잘못된 계정 ID입니다.");
  }
  return db.collection("players").doc(id);
}
async function writeAudit(uid, action, playerId, before, after, note = "") {
  await db.collection("admin_audit").add({
    actorUid: uid,
    action,
    playerId: playerId || null,
    note: cleanReason(note),
    before: before || null,
    after: after || null,
    at: admin.firestore.FieldValue.serverTimestamp()
  });
}
function isBlockedName(name) {
  const normalized = String(name || "").toLowerCase().replace(/[\s._-]/g, "");
  return BLOCKED_NAME_TERMS.some(term => normalized.includes(term.replace(/[\s._-]/g, "")));
}
function suspiciousLog(player) {
  const logs = Array.isArray(player && player.log) ? player.log : [];
  const now = Date.now();
  const recent = logs.filter(x => x && Number(x.at) > now - 60000);
  if (recent.length >= 16) return "짧은 시간에 비정상적으로 많은 점수 기록";
  if (logs.some(x => Number(x.score) > 100 || Number(x.score) < 0)) return "게임 점수 허용 범위 초과";
  if ((Number(player && player.plays) || 0) > logs.length + 5 && logs.length >= 20) {
    return "플레이 기록과 점수 기록 불일치";
  }
  return "";
}

exports.moderatePlayer = onDocumentWritten("players/{playerId}", async event => {
  const after = event.data && event.data.after;
  if (!after || !after.exists) return;
  const player = after.data() || {};
  if (player.moderation && ["banned", "review"].includes(player.moderation.status)) return;

  const nameReason = isBlockedName(player.name) ? "부적절한 닉네임" : "";
  const scoreReason = suspiciousLog(player);
  const reason = nameReason || scoreReason;
  if (!reason) return;

  await after.ref.set({
    moderation: {
      status: "banned",
      reason,
      detectedAt: admin.firestore.FieldValue.serverTimestamp(),
      source: "automatic"
    }
  }, { merge: true });
  if (player.ownerUid) {
    await db.collection("banned_users").doc(player.ownerUid).set({
      status: "banned", playerId: event.params.playerId, reason,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
  }

  await db.collection("admin_audit").add({
    actorUid: "system",
    action: "automatic-ban",
    playerId: event.params.playerId,
    note: reason,
    before: null,
    after: { name: player.name || "", status: "banned" },
    at: admin.firestore.FieldValue.serverTimestamp()
  });
});

exports.claimPlayer = onCall(async request => {
  const uid = requireAuth(request);
  const blockedUid = await db.collection("banned_users").doc(uid).get();
  if (blockedUid.exists) throw new HttpsError("permission-denied", "이 기기는 운영 정책 위반으로 이용이 정지되었습니다.");
  const data = request.data || {};
  const id = String(data.playerId || "");
  const name = String(data.name || "").trim().slice(0, 10);
  const ref = playerRef(id);
  if (!name || isBlockedName(name)) throw new HttpsError("invalid-argument", "사용할 수 없는 닉네임입니다.");
  let player;
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const current = snap.exists ? snap.data() : null;
    if (current && current.moderation && current.moderation.status === "banned") {
      throw new HttpsError("permission-denied", "정지된 계정입니다.");
    }
    if (current && current.ownerUid && current.ownerUid !== uid) {
      throw new HttpsError("already-exists", "이 닉네임은 다른 기기에 연결되어 있습니다.");
    }
    player = {
      ...(current || { s: {}, wins: 0, plays: 0, pts: 0, t: 0, xp: 0 }),
      name,
      ownerUid: uid
    };
    tx.set(ref, player);
  });
  return { ok: true, player };
});

exports.adminAction = onCall(async request => {
  const uid = requireAdmin(request);
  const data = request.data || {};
  const action = String(data.action || "");

  if (action === "check") {
    return { ok: true, uid, season: (await db.doc("meta/season").get()).data()?.n || 1 };
  }

  if (action === "listAudit") {
    const snap = await db.collection("admin_audit").orderBy("at", "desc").limit(40).get();
    return {
      items: snap.docs.map(doc => {
        const d = doc.data();
        return {
          id: doc.id,
          action: d.action || "",
          playerId: d.playerId || "",
          note: d.note || "",
          actorUid: d.actorUid || "",
          at: d.at && d.at.toMillis ? d.at.toMillis() : null,
          canRollback: !!d.before && !!d.playerId
        };
      })
    };
  }

  if (action === "deletePlayer") {
    const id = String(data.playerId || "");
    const ref = playerRef(id);
    const snap = await ref.get();
    if (!snap.exists) throw new HttpsError("not-found", "계정을 찾을 수 없습니다.");
    const before = snap.data();
    await writeAudit(uid, action, id, before, null, data.reason);
    await ref.delete();
    return { ok: true };
  }

  if (action === "setBan") {
    const id = String(data.playerId || "");
    const ref = playerRef(id);
    const snap = await ref.get();
    if (!snap.exists) throw new HttpsError("not-found", "계정을 찾을 수 없습니다.");
    const before = snap.data();
    const status = data.banned ? "banned" : "clear";
    const after = {
      ...before,
      moderation: data.banned
        ? { status, reason: cleanReason(data.reason) || "관리자 제재", detectedAt: admin.firestore.FieldValue.serverTimestamp(), source: "admin" }
        : { status: "clear", reason: "", clearedAt: admin.firestore.FieldValue.serverTimestamp(), source: "admin" }
    };
    await ref.set(after);
    if (before.ownerUid) {
      const bannedRef = db.collection("banned_users").doc(before.ownerUid);
      if (data.banned) await bannedRef.set({ status: "banned", playerId: id, reason: after.moderation.reason, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      else await bannedRef.delete();
    }
    await writeAudit(uid, action, id, before, after, data.reason);
    return { ok: true };
  }

  if (action === "adjustScore") {
    const id = String(data.playerId || "");
    const ref = playerRef(id);
    const snap = await ref.get();
    if (!snap.exists) throw new HttpsError("not-found", "계정을 찾을 수 없습니다.");
    const before = snap.data();
    const field = String(data.field || "");
    const delta = Number(data.delta);
    if (!Number.isFinite(delta) || !Number.isInteger(delta) || Math.abs(delta) > 1000000) {
      throw new HttpsError("invalid-argument", "점수 변경값은 -1,000,000~1,000,000 사이의 정수여야 합니다.");
    }
    const after = { ...before };
    if (field.startsWith("s.")) {
      const game = field.slice(2);
      if (!/^[a-z0-9_-]{1,40}$/.test(game)) throw new HttpsError("invalid-argument", "잘못된 게임 항목입니다.");
      after.s = { ...(before.s || {}) };
      after.s[game] = Math.max(0, (Number(after.s[game]) || 0) + delta);
    } else if (["pts", "cp", "xp", "dw"].includes(field)) {
      after[field] = Math.max(0, (Number(before[field]) || 0) + delta);
    } else {
      throw new HttpsError("invalid-argument", "허용되지 않은 점수 항목입니다.");
    }
    after.adminUpdatedAt = admin.firestore.FieldValue.serverTimestamp();
    await ref.set(after);
    await writeAudit(uid, action, id, before, after, field + " " + (delta > 0 ? "+" : "") + delta + " · " + cleanReason(data.reason));
    return { ok: true, value: field.startsWith("s.") ? after.s[field.slice(2)] : after[field] };
  }

  if (action === "rollback") {
    const auditId = String(data.auditId || "");
    if (!/^[A-Za-z0-9]{10,40}$/.test(auditId)) throw new HttpsError("invalid-argument", "잘못된 롤백 기록입니다.");
    const auditRef = db.collection("admin_audit").doc(auditId);
    const auditSnap = await auditRef.get();
    if (!auditSnap.exists) throw new HttpsError("not-found", "롤백 기록을 찾을 수 없습니다.");
    const record = auditSnap.data();
    if (!record.playerId || !record.before) throw new HttpsError("failed-precondition", "복원할 계정 스냅샷이 없습니다.");
    const ref = playerRef(record.playerId);
    const current = await ref.get();
    await ref.set(record.before);
    if (record.before.ownerUid) {
      const bannedRef = db.collection("banned_users").doc(record.before.ownerUid);
      if (record.before.moderation && record.before.moderation.status === "banned") {
        await bannedRef.set({ status: "banned", playerId: record.playerId, reason: record.before.moderation.reason || "복원된 제재", updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      } else {
        await bannedRef.delete();
      }
    }
    await writeAudit(uid, "rollback", record.playerId, current.exists ? current.data() : null, record.before, "원본 기록 " + auditId + " 복원");
    return { ok: true };
  }

  if (action === "setSeason") {
    const season = Number(data.season);
    if (!Number.isInteger(season) || season < 1 || season > 9999) {
      throw new HttpsError("invalid-argument", "시즌 번호는 1~9999 사이의 정수여야 합니다.");
    }
    const metaRef = db.doc("meta/season");
    const snap = await metaRef.get();
    const before = snap.exists ? snap.data() : { n: 1, hof: [], history: [] };
    const after = { ...before, n: season, seasonAdjustedAt: admin.firestore.FieldValue.serverTimestamp() };
    if (data.resetChampionship === true) {
      const players = await db.collection("players").get();
      const ranked = players.docs
        .map(doc => ({ id: doc.id, ...doc.data() }))
        .filter(p => (Number(p.cm) || 0) > 0)
        .sort((a, b) => (Number(b.cp) || 0) - (Number(a.cp) || 0));
      const champion = ranked[0];
      if (season !== (Number(before.n) || 1) && champion) {
        after.hof = [
          ...(Array.isArray(before.hof) ? before.hof : []),
          { s: Number(before.n) || 1, name: champion.name || "Unknown", points: Number(champion.cp) || 0,
            wins: Number(champion.cw) || 0, matches: Number(champion.cm) || 0 }
        ];
      }
      for (let i = 0; i < players.docs.length; i += 450) {
        const batch = db.batch();
        players.docs.slice(i, i + 450).forEach(doc => batch.set(doc.ref, {
          cp: 0, cw: 0, cd: 0, cl: 0, cm: 0
        }, { merge: true }));
        await batch.commit();
      }
    }
    await metaRef.set(after);
    await writeAudit(uid, "setSeason", null, before, after,
      "시즌 번호 " + (before.n || 1) + " → " + season + (data.resetChampionship ? " · 챔피언십 점수 초기화" : " · 점수 유지"));
    return { ok: true, season };
  }

  throw new HttpsError("invalid-argument", "지원하지 않는 관리자 작업입니다.");
});
