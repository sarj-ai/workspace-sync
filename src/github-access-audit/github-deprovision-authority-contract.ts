import { z } from "zod";

import { GitHubOrganizationInvitationSchema } from "../github/organization-membership-reader.ts";
import {
  GitHubActorSchema,
  GitHubCollaboratorSchema,
  GitHubOrganizationSchema,
  GitHubTeamMemberSchema,
  GitHubTeamSchema,
} from "./github-contracts.ts";

export const GitHubDeprovisionCapabilitySchema = z.enum([
  "invitations",
  "members",
  "organization",
  "outside_collaborators",
  "repositories",
  "teams",
]);
const GitHubDeprovisionMemberRoleSchema = z.enum(["admin", "member"]);

export const GitHubDeprovisionAuthoritySchema = z.strictObject({
  capturedAt: z.iso.datetime({ offset: true }),
  errors: z.array(
    z.strictObject({
      capability: GitHubDeprovisionCapabilitySchema,
      code: z.string().min(1),
      message: z.string().min(1),
    }),
  ),
  invitations: z.array(GitHubOrganizationInvitationSchema),
  members: z.array(
    GitHubActorSchema.extend({ role: GitHubDeprovisionMemberRoleSchema }),
  ),
  organization: GitHubOrganizationSchema.pick({
    id: true,
    login: true,
    "owned_private_repos": true,
    "public_repos": true,
  }).nullable(),
  outsideCollaborators: z.array(GitHubActorSchema),
  repositories: z.array(
    z.strictObject({
      directCollaborators: z.array(GitHubCollaboratorSchema),
      "full_name": z.string().min(1),
      id: z.number().int().positive(),
    }),
  ),
  teams: z.array(
    GitHubTeamSchema.extend({
      directMembers: z.array(GitHubTeamMemberSchema),
      maintainers: z.array(GitHubTeamMemberSchema),
    }),
  ),
});

export type GitHubDeprovisionAuthority = z.output<
  typeof GitHubDeprovisionAuthoritySchema
>;
