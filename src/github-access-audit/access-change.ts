import { normalizeIdentityEmail as normalize } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleAuditUser } from "./google-contracts.ts";
import type { ProposedAccessChange } from "./model.ts";
import { initialGrace } from "./removal-grace.ts";

export function plannedChange(
  kind: ProposedAccessChange["kind"],
  email: string,
  login: string | undefined,
  target: string,
  desired: Exclude<ProposedAccessChange["desired"], null>,
  authorityPath: string[],
  reason: string,
  sourceComplete: boolean,
  user?: GoogleAuditUser,
  githubId?: number,
): ProposedAccessChange {
  const removal = kind === "org_remove" || kind === "team_remove";
  const immediate = Boolean(user?.suspended || user?.archived || user?.deleted);
  const blockers = !login ? ["No unambiguous GitHub identity correlation"] : [];
  if (removal && !immediate) {
    blockers.push(
      "Removal age is unknown; Google Reports evidence did not establish elapsed grace",
    );
  }
  if (!sourceComplete)
    blockers.push("At least one authoritative source snapshot is incomplete");
  return {
    authorityPath,
    blockers,
    current: kind.endsWith("remove") ? "present" : "absent",
    desired,
    grace: initialGrace(removal, immediate),
    id: `${kind}:${target}:${normalize(email)}`,
    kind,
    privilege: desired,
    reason,
    safelyActionable: false,
    subject: {
      email: normalize(email),
      ...(user && { googleId: user.id }),
      ...(githubId && { githubId }),
      ...(login && { login }),
    },
    target,
  };
}

export function exceptionChange(
  category: string,
  actor: { id: number; login: string },
  target: string,
  privilege: ProposedAccessChange["privilege"],
  reason: string,
): ProposedAccessChange {
  return {
    authorityPath: [`github:${category}`],
    blockers: ["Human approval and an explicit exception record are required"],
    current: "present",
    desired: null,
    grace: "not_applicable",
    id: `policy_exception:${category}:${target}:${actor.login}`,
    kind: "policy_exception",
    privilege,
    reason,
    safelyActionable: false,
    subject: { githubId: actor.id, login: actor.login },
    target,
  };
}
