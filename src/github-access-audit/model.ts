import { z } from "zod";

import { GitHubOrganizationInvitationSchema } from "../github/organization-membership-reader.ts";
import {
  GitHubActorSchema,
  GitHubCollaboratorSchema,
  GitHubOrganizationSchema,
  GitHubRepositorySchema,
  GitHubTeamGrantSchema,
  GitHubTeamSchema,
} from "./github-contracts.ts";

export const GraceClassificationSchema = z.enum([
  "age_unknown",
  "conflicted",
  "grace_elapsed",
  "immediate_authoritative",
  "not_applicable",
  "pending_grace",
]);
export const ChangeKindSchema = z.enum([
  "org_add",
  "org_remove",
  "policy_exception",
  "team_add",
  "team_remove",
]);
export const RepositoryPermissionSchema = z.enum([
  "admin",
  "maintain",
  "none",
  "pull",
  "push",
  "triage",
  "unknown",
]);
const CurrentAccessStateSchema = z.enum(["absent", "present"]).nullable();
const DesiredAccessStateSchema = z
  .enum(["blocked", "member", "none"])
  .nullable();
const PrivilegeSchema = z.union([
  RepositoryPermissionSchema,
  z.enum(["blocked", "maintainer", "member", "repository_specific"]),
]);
const ProposedAccessChangeSchema = z.object({
  authorityPath: z.array(z.string()),
  blockers: z.array(z.string()),
  current: CurrentAccessStateSchema,
  desired: DesiredAccessStateSchema,
  grace: GraceClassificationSchema,
  id: z.string().min(1),
  kind: ChangeKindSchema,
  privilege: PrivilegeSchema,
  reason: z.string().min(1),
  safelyActionable: z.boolean(),
  subject: z.object({
    email: z.email().optional(),
    githubId: z.number().int().positive().optional(),
    googleId: z.string().min(1).optional(),
    login: z.string().min(1).optional(),
  }),
  target: z.string().min(1),
});
const EffectiveRepositoryAccessSchema = z.object({
  after: RepositoryPermissionSchema,
  before: RepositoryPermissionSchema,
  login: z.string().min(1),
  repository: z.string().min(1),
  sourcesAfter: z.array(z.string()),
  sourcesBefore: z.array(z.string()),
});
const AuditedRepositorySchema = GitHubRepositorySchema.extend({
  directCollaborators: z.array(GitHubCollaboratorSchema),
  teamGrants: z.array(GitHubTeamGrantSchema),
});
const AuditedTeamSchema = GitHubTeamSchema.extend({
  directMembers: z.array(GitHubActorSchema),
  maintainers: z.array(GitHubActorSchema),
});

export const GithubAccessAuditReportSchema = z.object({
  complete: z.boolean(),
  contentHash: z.string().regex(/^[a-f0-9]{64}$/u),
  counts: z.record(z.string(), z.number().int().nonnegative()),
  errors: z.array(z.string()),
  generatedAt: z.iso.datetime(),
  identityMismatches: z.array(
    z.object({
      email: z.email().optional(),
      login: z.string().min(1).optional(),
      reason: z.string().min(1),
    }),
  ),
  inventory: z.object({
    bots: z.array(z.string()),
    deletedGoogleUsers: z.array(z.email()),
    directRepositoryGrants: z.array(
      z.object({
        customRoleName: z.string().min(1).optional(),
        unresolvedDirectRole: z.literal(true).optional(),
        login: z.string().min(1),
        permission: RepositoryPermissionSchema,
        repository: z.string().min(1),
      }),
    ),
    internalRepositories: z.array(z.string()),
    invitations: z.array(GitHubOrganizationInvitationSchema),
    maintainers: z.array(
      z.object({ login: z.string().min(1), team: z.string().min(1) }),
    ),
    githubExcludedGoogleGroups: z.array(
      z.object({ groupEmail: z.email(), members: z.array(z.email()) }),
    ),
    organization: GitHubOrganizationSchema.nullable(),
    orgOwners: z.array(z.string()),
    outsideCollaborators: z.array(z.string()),
    repositories: z.array(AuditedRepositorySchema),
    suspendedGoogleUsers: z.array(z.email()),
    teams: z.array(AuditedTeamSchema),
    unmanagedGithubTeams: z.array(z.string()),
    unmappedGoogleGroups: z.array(z.string()),
  }),
  policyVersion: z.string().min(1),
  proposedChanges: z.array(ProposedAccessChangeSchema),
  repositoryAccess: z.array(EffectiveRepositoryAccessSchema),
  runId: z.uuid(),
  samlScimReadiness: z.object({
    blockers: z.array(z.string()),
    exactNameIdMatchesUserName: z.boolean().nullable(),
    samlIdentityDataAvailable: z.boolean(),
    scimIdentityDataAvailable: z.boolean(),
  }),
  sourceTimestamps: z.object({
    github: z.iso.datetime(),
    google: z.iso.datetime(),
  }),
  warnings: z.array(z.string()),
});

export type EffectiveRepositoryAccess = z.infer<
  typeof EffectiveRepositoryAccessSchema
>;
export type GithubAccessAuditReport = z.infer<
  typeof GithubAccessAuditReportSchema
>;
export type ProposedAccessChange = z.infer<typeof ProposedAccessChangeSchema>;
export type RepositoryPermission = z.infer<typeof RepositoryPermissionSchema>;
