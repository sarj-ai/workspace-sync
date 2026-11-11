/** Database capabilities consumed by the workspace stores; rows remain untrusted. */
export interface WorkspaceQueryResult {
  meta: { changes: number };
  results: unknown[];
}

export interface WorkspaceStatement<Statement> {
  all(): Promise<WorkspaceQueryResult>;
  bind(...values: unknown[]): Statement;
  first(): Promise<unknown>;
  run(): Promise<WorkspaceQueryResult>;
}

export interface WorkspaceDatabaseSession<
  Statement extends WorkspaceStatement<Statement>,
> {
  batch(statements: Statement[]): Promise<WorkspaceQueryResult[]>;
  prepare(sql: string): Statement;
}

export interface WorkspaceDatabase<
  Statement extends WorkspaceStatement<Statement>,
> {
  withSession(constraint?: string): WorkspaceDatabaseSession<Statement>;
}
