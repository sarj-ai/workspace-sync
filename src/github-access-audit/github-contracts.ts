import { z } from "zod";

import { GitHubOrganizationActorSchema } from "../github/organization-membership-reader.ts";

export const GitHubActorSchema = GitHubOrganizationActorSchema;
export const GitHubOrganizationSchema = z.object({
  "default_repository_permission": z
    .enum(["admin", "none", "read", "write"])
    .nullish(),
  id: z.number().int().positive(),
  login: z.string().min(1),
  "members_can_create_repositories": z.boolean().optional(),
  "owned_private_repos": z.number().int().nonnegative().optional(),
  "public_repos": z.number().int().nonnegative().optional(),
});
export const GitHubPermissionFlagsSchema = z.object({
  admin: z.boolean(),
  maintain: z.boolean().optional(),
  pull: z.boolean(),
  push: z.boolean(),
  triage: z.boolean().optional(),
});
export const GitHubTeamSchema = z.object({
  id: z.number().int().positive(),
  name: z.string().min(1),
  parent: z
    .object({ id: z.number().int().positive(), slug: z.string().min(1) })
    .nullable(),
  privacy: z.enum(["closed", "secret"]),
  slug: z.string().min(1),
});
export const GitHubTeamMemberSchema = GitHubActorSchema.extend({
  inherited: z.boolean().optional(),
});
export const GitHubRepositorySchema = z.object({
  archived: z.boolean(),
  "full_name": z.string().min(1),
  id: z.number().int().positive(),
  name: z.string().min(1),
  permissions: GitHubPermissionFlagsSchema.optional(),
  visibility: z.enum(["internal", "private", "public"]),
});
export const GitHubTeamGrantSchema = z.object({
  id: z.number().int().positive(),
  permission: z.enum(["admin", "maintain", "pull", "push", "triage"]),
  slug: z.string().min(1),
});
export const GitHubCollaboratorSchema = GitHubActorSchema.extend({
  customRoleName: z.string().min(1).optional(),
  unresolvedDirectRole: z.literal(true).optional(),
  permissions: GitHubPermissionFlagsSchema.optional(),
});
export const GitHubScimPageSchema = z.object({
  itemsPerPage: z.number().int().nonnegative(),
  Resources: z.array(
    z.object({
      active: z.boolean().optional().default(true),
      externalId: z.string().optional(),
      id: z.string().min(1),
      userName: z.string().min(1),
    }),
  ),
  startIndex: z.number().int().positive(),
  totalResults: z.number().int().nonnegative(),
});
export const GitHubSamlResponseSchema = z.object({
  data: z
    .object({
      organization: z
        .object({
          samlIdentityProvider: z
            .object({
              externalIdentities: z.object({
                nodes: z.array(
                  z.object({
                    guid: z.string().min(1),
                    samlIdentity: z
                      .object({ nameId: z.string().nullable() })
                      .nullable(),
                    user: z
                      .object({
                        databaseId: z.number().int().positive().optional(),
                        login: z.string().min(1),
                      })
                      .nullable(),
                  }),
                ),
                pageInfo: z.object({
                  endCursor: z.string().nullable(),
                  hasNextPage: z.boolean(),
                }),
              }),
            })
            .nullable(),
        })
        .nullable(),
    })
    .nullable(),
  errors: z.array(z.object({ message: z.string() })).optional(),
});
