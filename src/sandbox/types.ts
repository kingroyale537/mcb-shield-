export interface SandboxExecutionRequest {
  toolName: string;
  args: Record<string, unknown>;
  workspaceDir: string;
  timeoutMs: number;
  envWhitelist?: string[];
  allowNetwork?: boolean;
  maxMemoryMb?: number;
}

export interface SandboxExecutionResult {
  success: boolean;
  output: unknown;
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  executionTimeMs: number;
  sandboxed: boolean;
  driver: string;
  filesMutated?: string[];
  error?: string;
}

export interface SandboxDriver {
  readonly name: string;
  isAvailable(): Promise<boolean>;
  execute(request: SandboxExecutionRequest): Promise<SandboxExecutionResult>;
  cleanup?(): Promise<void>;
}
