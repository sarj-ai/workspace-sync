import { normalizeIdentityEmail as normalize } from "../identity-sync/normalize-identity-email.ts";
import type { GitHubAccessSnapshot } from "./git-hub-access-audit-client.ts";
import type { GoogleAuditUser } from "./google-contracts.ts";

export interface IdentityMismatch {
  email?: string;
  login?: string;
  reason: string;
}

export interface IdentityCorrelation {
  emailByLogin: Map<string, string>;
  loginByEmail: Map<string, string>;
  mismatches: IdentityMismatch[];
}

export function correlateIdentities(
  github: GitHubAccessSnapshot,
  users: Map<string, GoogleAuditUser>,
): IdentityCorrelation {
  const loginByEmail = new Map<string, string>();
  const emailByLogin = new Map<string, string>();
  const loginsByEmail = new Map<string, Set<string>>();
  const emailsByLogin = new Map<string, Set<string>>();
  const mismatches: IdentityMismatch[] = [];
  for (const identity of github.samlExternalIdentities) {
    indexSamlIdentity(
      identity,
      users,
      loginsByEmail,
      emailsByLogin,
      mismatches,
    );
  }
  resolveEmailMappings(loginsByEmail, loginByEmail, mismatches);
  resolveLoginMappings(emailsByLogin, loginsByEmail, emailByLogin, mismatches);
  for (const member of github.members) {
    if (!emailByLogin.has(member.login)) {
      mismatches.push({
        login: member.login,
        reason:
          "GitHub organization member has no unambiguous SAML external identity",
      });
    }
  }
  return { emailByLogin, loginByEmail, mismatches };
}

function indexSamlIdentity(
  identity: GitHubAccessSnapshot["samlExternalIdentities"][number],
  users: Map<string, GoogleAuditUser>,
  loginsByEmail: Map<string, Set<string>>,
  emailsByLogin: Map<string, Set<string>>,
  mismatches: IdentityMismatch[],
): void {
  if (!identity.nameId) return;
  const email = normalize(identity.nameId);
  if (!identity.login) {
    mismatches.push({
      email,
      reason: "SAML identity is not linked to a GitHub user",
    });
    return;
  }
  const user = users.get(email);
  if (!user) {
    mismatches.push({
      email,
      login: identity.login,
      reason: "SAML NameID does not resolve to a Google user or alias",
    });
    return;
  }
  const canonical = normalize(user.primaryEmail);
  for (const candidate of [canonical, ...user.aliases.map(normalize)]) {
    addToSetMap(loginsByEmail, candidate, identity.login);
  }
  addToSetMap(emailsByLogin, identity.login, canonical);
}

function addToSetMap(
  index: Map<string, Set<string>>,
  key: string,
  value: string,
): void {
  const values = index.get(key) ?? new Set<string>();
  values.add(value);
  index.set(key, values);
}

function resolveEmailMappings(
  candidates: Map<string, Set<string>>,
  output: Map<string, string>,
  mismatches: IdentityMismatch[],
): void {
  for (const [email, logins] of candidates) {
    const [login] = logins;
    if (logins.size === 1 && login) output.set(email, login);
    else
      mismatches.push({
        email,
        reason: "Google identity maps to multiple GitHub logins",
      });
  }
}

function resolveLoginMappings(
  candidates: Map<string, Set<string>>,
  loginsByEmail: Map<string, Set<string>>,
  output: Map<string, string>,
  mismatches: IdentityMismatch[],
): void {
  for (const [login, emails] of candidates) {
    const [email] = emails;
    if (emails.size === 1 && email && loginsByEmail.get(email)?.size === 1) {
      output.set(login, email);
    } else {
      mismatches.push({
        login,
        reason: "GitHub login does not map one-to-one to a Google identity",
      });
    }
  }
}
