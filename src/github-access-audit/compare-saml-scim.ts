import type { GitHubAccessSnapshot } from "./git-hub-access-audit-client.ts";

export interface SamlScimComparison {
  blockers: string[];
  exact: boolean | null;
}

export function compareSamlScim(
  github: GitHubAccessSnapshot,
): SamlScimComparison {
  if (
    github.errors.some(
      (error) =>
        error.capability === "saml_external_identities" ||
        error.capability === "scim_identities",
    )
  ) {
    return { blockers: [], exact: null };
  }
  const blockers: string[] = [];
  const samlNames = github.samlExternalIdentities.flatMap((identity) =>
    identity.nameId === null ? [] : [identity.nameId],
  );
  const activeScimNames = github.scimIdentities
    .filter((identity) => identity.active)
    .map((identity) => identity.userName);
  const linkedLogins = github.samlExternalIdentities.flatMap((identity) =>
    identity.login === null ? [] : [identity.login],
  );
  if (
    github.samlExternalIdentities.some((identity) => identity.nameId === null)
  ) {
    blockers.push("At least one SAML identity has no NameID.");
  }
  if (
    github.samlExternalIdentities.some((identity) => identity.login === null)
  ) {
    blockers.push("At least one SAML identity is not linked to a GitHub user.");
  }
  if (new Set(linkedLogins).size !== linkedLogins.length) {
    blockers.push(
      "A GitHub login is linked to multiple SAML external identities.",
    );
  }
  if (github.scimIdentities.some((identity) => !identity.active)) {
    blockers.push("At least one inactive SCIM identity remains provisioned.");
  }
  if (new Set(samlNames).size !== samlNames.length) {
    blockers.push(
      "Duplicate SAML NameID values prevent one-to-one identity matching.",
    );
  }
  if (new Set(activeScimNames).size !== activeScimNames.length) {
    blockers.push(
      "Duplicate active SCIM userName values prevent one-to-one identity matching.",
    );
  }
  const saml = new Set(samlNames);
  const scim = new Set(activeScimNames);
  const missingInScim = [...saml.difference(scim)];
  const missingInSaml = [...scim.difference(saml)];
  if (missingInScim.length > 0) {
    blockers.push(
      `SAML NameIDs missing from SCIM: ${missingInScim.toSorted(compareString).join(", ")}`,
    );
  }
  if (missingInSaml.length > 0) {
    blockers.push(
      `SCIM userNames missing from SAML: ${missingInSaml.toSorted(compareString).join(", ")}`,
    );
  }
  if (
    github.members.length > 0 &&
    (samlNames.length === 0 || activeScimNames.length === 0)
  ) {
    blockers.push(
      "Organization members exist but the SAML/SCIM identity inventory is empty.",
    );
  }
  return { blockers, exact: blockers.length === 0 };
}

function compareString(left: string, right: string): number {
  return left.localeCompare(right);
}
