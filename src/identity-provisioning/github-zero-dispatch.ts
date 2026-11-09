import { z } from "zod";

export const GithubDispatchClaimSchema = z.strictObject({
  protocol: z.literal("github-single-operation/v1"),
  claimId: z.uuidv4(),
  operationHash: z.string().regex(/^[a-f0-9]{64}$/u),
});
export type GithubDispatchClaim = z.output<typeof GithubDispatchClaimSchema>;
export const GithubPrewriteRefusalCategorySchema = z.enum([
  "scope",
  "credentials",
  "provider-observation",
  "final-authority",
]);
export type GithubPrewriteRefusalCategory = z.output<
  typeof GithubPrewriteRefusalCategorySchema
>;
