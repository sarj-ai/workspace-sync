import { z } from "zod";

import {
  type JsonValue,
  JsonValueSchema,
  type ManagedChange,
  ManagedChangeSchema,
  type OperationActor,
  type OperationDescriptor,
  OperationDescriptorSchema,
  type OperationDiagnostic,
  type OperationDiscoveryMetadata,
  OperationDiscoveryMetadataSchema,
  OperationIdentifierSchema,
  type SourceFingerprint,
} from "./schemas.ts";

export interface OperationContext {
  actor: OperationActor;
  environment: string;
  now: Date;
}

export interface OperationPlanDraft<Details extends JsonValue> {
  applicable: boolean;
  changes: TypedManagedChange<Details>[];
  diagnostics: OperationDiagnostic[];
  sourceFingerprints: SourceFingerprint[];
}

export type TypedManagedChange<Details extends JsonValue> = Omit<
  ManagedChange,
  "details"
> & {
  details: Details;
};

interface OperationDefinitionBaseOptions<
  InputSchema extends z.ZodType<JsonValue>,
  DetailsSchema extends z.ZodType<JsonValue>,
> {
  readonly actionIds?: readonly string[];
  buildPlan: (
    input: z.output<InputSchema>,
    context: OperationContext,
  ) => Promise<OperationPlanDraft<z.output<DetailsSchema>>>;
  detailsSchema: DetailsSchema;
  inputSchema: InputSchema;
  metadata: OperationDiscoveryMetadata;
  name: string;
  policyVersion: string;
  ttlSeconds?: number;
}

type OperationApplyChange<DetailsSchema extends z.ZodType<JsonValue>> = (
  change: TypedManagedChange<z.output<DetailsSchema>>,
  context: OperationContext,
) => Promise<void>;

type OperationApplyDefinitionOptions<
  InputSchema extends z.ZodType<JsonValue>,
  DetailsSchema extends z.ZodType<JsonValue>,
> = Omit<
  OperationDefinitionBaseOptions<InputSchema, DetailsSchema>,
  "metadata"
> & {
  readonly applyChange: OperationApplyChange<DetailsSchema>;
  readonly metadata: OperationDiscoveryMetadata & {
    readonly supportsApply: true;
  };
  readonly readManagedSlice: (
    change: TypedManagedChange<z.output<DetailsSchema>>,
    context: OperationContext,
  ) => Promise<JsonValue | null>;
  readonly readSourceFingerprints: (
    input: z.output<InputSchema>,
    context: OperationContext,
  ) => Promise<SourceFingerprint[]>;
};

type OperationPlanOnlyDefinitionOptions<
  InputSchema extends z.ZodType<JsonValue>,
  DetailsSchema extends z.ZodType<JsonValue>,
> = Omit<
  OperationDefinitionBaseOptions<InputSchema, DetailsSchema>,
  "metadata"
> & {
  readonly applyChange?: never;
  readonly metadata: OperationDiscoveryMetadata & {
    readonly supportsApply: false;
  };
  readonly readManagedSlice?: never;
  readonly readSourceFingerprints?: never;
};

export type OperationDefinitionOptions<
  InputSchema extends z.ZodType<JsonValue>,
  DetailsSchema extends z.ZodType<JsonValue>,
> =
  | OperationApplyDefinitionOptions<InputSchema, DetailsSchema>
  | OperationPlanOnlyDefinitionOptions<InputSchema, DetailsSchema>;

interface RegisteredOperationBase {
  actionIds: ReadonlySet<string>;
  buildPlan(
    input: unknown,
    context: OperationContext,
  ): Promise<{
    draft: OperationPlanDraft<JsonValue>;
    input: JsonValue;
  }>;
  metadata: OperationDiscoveryMetadata;
  name: string;
  parseInput(input: unknown): JsonValue;
  policyVersion: string;
  ttlSeconds: number;
}

export interface RegisteredApplyOperation extends RegisteredOperationBase {
  applyChange(change: ManagedChange, context: OperationContext): Promise<void>;
  metadata: OperationDiscoveryMetadata & { supportsApply: true };
  readManagedSlice(
    change: ManagedChange,
    context: OperationContext,
  ): Promise<JsonValue | null>;
  readSourceFingerprints(
    input: unknown,
    context: OperationContext,
  ): Promise<SourceFingerprint[]>;
}

export interface RegisteredPlanOnlyOperation extends RegisteredOperationBase {
  metadata: OperationDiscoveryMetadata & { supportsApply: false };
}

export type RegisteredOperation =
  | RegisteredApplyOperation
  | RegisteredPlanOnlyOperation;

export class OperationInputError extends Error {
  constructor(options?: ErrorOptions) {
    super("Operation input is invalid.", options);
    this.name = "OperationInputError";
  }
}
const ComponentIdentifierSchema = OperationIdentifierSchema.max(200);

export class OperationContractError extends Error {
  readonly component: string;

  constructor(component: string, options?: ErrorOptions) {
    super(`Operation contract is invalid at ${component}.`, options);
    this.name = "OperationContractError";
    this.component = ComponentIdentifierSchema.parse(component);
  }
}

export class OperationSourceError extends Error {
  readonly component: string;

  constructor(component: string, options?: ErrorOptions) {
    super(`Authoritative system is unavailable at ${component}.`, options);
    this.name = "OperationSourceError";
    this.component = ComponentIdentifierSchema.parse(component);
  }
}

const DEFAULT_TTL_SECONDS = 10 * 60;
const MAX_TTL_SECONDS = 15 * 60;

const PolicyVersionSchema = z.string().trim().min(1).max(100);

const PlanTtlSecondsSchema = z.number().int().positive().max(MAX_TTL_SECONDS);

export function defineOperation<
  InputSchema extends z.ZodType<JsonValue>,
  DetailsSchema extends z.ZodType<JsonValue>,
>(
  options: OperationDefinitionOptions<InputSchema, DetailsSchema>,
): RegisteredOperation {
  const name = OperationIdentifierSchema.parse(options.name);
  const policyVersion = PolicyVersionSchema.parse(options.policyVersion);
  const metadata = OperationDiscoveryMetadataSchema.parse(options.metadata);
  if (metadata.supportsApply !== (options.applyChange !== undefined)) {
    throw new Error(
      `Operation ${name} APPLY capability does not match its implementation`,
    );
  }
  const ttlSeconds = PlanTtlSecondsSchema.parse(
    options.ttlSeconds ?? DEFAULT_TTL_SECONDS,
  );
  const actionIds = new Set(
    (options.actionIds ?? []).map((actionId) =>
      ManagedChangeSchema.shape.actionId.parse(actionId),
    ),
  );
  if (actionIds.size !== (options.actionIds ?? []).length) {
    throw new Error(`Operation ${name} declares duplicate action ids`);
  }

  function parseInput(input: unknown): JsonValue {
    return JsonValueSchema.parse(options.inputSchema.parse(input));
  }

  function parseTypedChange(
    input: unknown,
  ): TypedManagedChange<z.output<DetailsSchema>> {
    const change = ManagedChangeSchema.parse(input);
    return { ...change, details: options.detailsSchema.parse(change.details) };
  }

  const base: Omit<RegisteredOperationBase, "metadata"> = {
    actionIds,
    async buildPlan(input, context) {
      const parsedInput = options.inputSchema.safeParse(input);
      if (!parsedInput.success) {
        throw new OperationInputError({ cause: parsedInput.error });
      }
      const typedInput = parsedInput.data;
      const draft = await options.buildPlan(typedInput, context);
      try {
        return {
          draft: {
            applicable: draft.applicable,
            changes: draft.changes.map((change) =>
              ManagedChangeSchema.parse(parseTypedChange(change)),
            ),
            diagnostics: draft.diagnostics,
            sourceFingerprints: draft.sourceFingerprints,
          },
          input: JsonValueSchema.parse(typedInput),
        };
      } catch (error) {
        if (
          error instanceof OperationContractError ||
          error instanceof OperationSourceError
        )
          throw error;
        throw new OperationContractError(`${name}.plan-contract`, {
          cause: error,
        });
      }
    },
    name,
    parseInput,
    policyVersion,
    ttlSeconds,
  };
  if (!isApplyDefinition(options)) {
    return { ...base, metadata: { ...metadata, supportsApply: false } };
  }
  const { applyChange, readManagedSlice, readSourceFingerprints } = options;
  return {
    ...base,
    applyChange: (change, context) =>
      applyChange(parseTypedChange(change), context),
    metadata: { ...metadata, supportsApply: true },
    async readManagedSlice(change, context) {
      return JsonValueSchema.nullable().parse(
        await readManagedSlice(parseTypedChange(change), context),
      );
    },
    readSourceFingerprints(input, context) {
      return readSourceFingerprints(options.inputSchema.parse(input), context);
    },
  };
}

function isApplyDefinition<
  InputSchema extends z.ZodType<JsonValue>,
  DetailsSchema extends z.ZodType<JsonValue>,
>(
  options: OperationDefinitionOptions<InputSchema, DetailsSchema>,
): options is OperationApplyDefinitionOptions<InputSchema, DetailsSchema> {
  return options.metadata.supportsApply;
}

export interface OperationCatalog {
  get(name: string): null | RegisteredOperation;
  list(): OperationDescriptor[];
  register(operation: RegisteredOperation): void;
}

export class OperationRegistry implements OperationCatalog {
  readonly #operations = new Map<string, RegisteredOperation>();

  constructor(operations: readonly RegisteredOperation[] = []) {
    for (const operation of operations) this.register(operation);
  }

  get(name: string): null | RegisteredOperation {
    return this.#operations.get(name) ?? null;
  }

  list(): OperationDescriptor[] {
    return this.#operations
      .values()
      .map((operation) =>
        OperationDescriptorSchema.parse({
          operationId: operation.name,
          ...operation.metadata,
        }),
      )
      .toArray()
      .toSorted((left, right) =>
        left.operationId.localeCompare(right.operationId),
      );
  }

  register(operation: RegisteredOperation): void {
    if (this.#operations.has(operation.name)) {
      throw new Error(`Operation ${operation.name} is already registered`);
    }
    this.#operations.set(operation.name, operation);
  }
}
