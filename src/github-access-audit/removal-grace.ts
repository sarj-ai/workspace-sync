import { normalizeIdentityEmail as normalize } from "../identity-sync/normalize-identity-email.ts";
import type {
  GoogleAuditUser,
  GoogleAuthoritySnapshot,
} from "./google-contracts.ts";
import type { ProposedAccessChange } from "./model.ts";

const ADD_EVENTS: ReadonlySet<string> = new Set([
  "ADD_GROUP_MEMBER",
  "GROUP_MEMBER_ADD",
]);
const REMOVE_EVENTS: ReadonlySet<string> = new Set([
  "REMOVE_GROUP_MEMBER",
  "GROUP_MEMBER_DELETE",
  "GROUP_MEMBER_REMOVE",
]);

export function initialGrace(
  removal: boolean,
  immediate: boolean,
): ProposedAccessChange["grace"] {
  if (!removal) return "not_applicable";
  return immediate ? "immediate_authoritative" : "age_unknown";
}

export function classifyRemovalGrace(
  user: GoogleAuditUser | undefined,
  email: string | undefined,
  targetGroupEmail: string,
  reports: GoogleAuthoritySnapshot["reports"],
  now: Date,
  policy: { membershipGraceMs: number; reportsIngestionMarginMs: number },
): ProposedAccessChange["grace"] {
  if (user?.suspended || user?.archived || user?.deleted)
    return "immediate_authoritative";
  if (!email || reports.status !== "available") return "age_unknown";
  const relevant = reports.events
    .filter(
      (event) =>
        event.subjectEmail !== undefined &&
        event.groupEmail !== undefined &&
        normalize(event.subjectEmail) === normalize(email) &&
        normalize(event.groupEmail) === normalize(targetGroupEmail) &&
        (ADD_EVENTS.has(event.name.toUpperCase()) ||
          REMOVE_EVENTS.has(event.name.toUpperCase())),
    )
    .map((event) => ({ ...event, occurredAt: Date.parse(event.time) }))
    .filter((event) => Number.isFinite(event.occurredAt))
    .toSorted((left, right) => right.occurredAt - left.occurredAt);
  const removal = relevant.find((event) =>
    REMOVE_EVENTS.has(event.name.toUpperCase()),
  );
  if (!removal) return "age_unknown";
  if (
    relevant.some(
      (event) =>
        ADD_EVENTS.has(event.name.toUpperCase()) &&
        event.occurredAt >= removal.occurredAt,
    )
  ) {
    return "conflicted";
  }
  const ageMs = now.getTime() - removal.occurredAt;
  if (ageMs < 0) return "conflicted";
  return ageMs >= policy.membershipGraceMs + policy.reportsIngestionMarginMs
    ? "grace_elapsed"
    : "pending_grace";
}
