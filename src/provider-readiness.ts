import { z } from "zod";

export const LinearTenantReadinessCodeSchema = z.enum([
  "linear_organization_id_mismatch",
  "linear_organization_id_unpinned",
  "linear_organization_url_key_mismatch",
]);

export const ProviderReadinessContextSchema = z.strictObject({
  "error_code": LinearTenantReadinessCodeSchema,
  kind: z.literal("linear_tenant"),
  "observed_organization_id": z.uuid(),
  "observed_url_key": z
    .string()
    .trim()
    .regex(/^[a-z0-9-]+$/)
    .max(100),
});
export type ProviderReadinessContext = z.output<
  typeof ProviderReadinessContextSchema
>;

export function validateProviderReadinessDiagnosticContext(
  diagnostic: { code: string; context?: ProviderReadinessContext | undefined },
  refinement: z.RefinementCtx,
): void {
  if (
    diagnostic.code === "provider_readiness" &&
    diagnostic.context === undefined
  ) {
    refinement.addIssue({
      code: "custom",
      message: "provider_readiness requires a typed context",
      path: ["context"],
    });
  }
  if (
    diagnostic.code !== "provider_readiness" &&
    diagnostic.context !== undefined
  ) {
    refinement.addIssue({
      code: "custom",
      message: "typed provider context is reserved for provider_readiness",
      path: ["context"],
    });
  }
}

export class ProviderReadinessError extends Error {
  readonly context: ProviderReadinessContext;

  constructor(context: ProviderReadinessContext, options?: ErrorOptions) {
    const parsed = ProviderReadinessContextSchema.parse(context);
    super(parsed["error_code"], options);
    this.name = "ProviderReadinessError";
    this.context = parsed;
  }
}
