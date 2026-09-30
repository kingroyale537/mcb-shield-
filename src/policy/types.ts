export type PolicyAction = 'allow' | 'block' | 'sandbox' | 'require_approval';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface PathCondition {
  allowed?: string[];
  denied?: string[];
  allowSubdirectories?: boolean;
}

export interface CommandCondition {
  allowed?: string[];
  denied?: string[];
  denyPatterns?: string[]; // Regex patterns
}

export interface NetworkCondition {
  allowOutbound?: boolean;
  allowedHosts?: string[];
  deniedHosts?: string[];
}

export interface RateLimitCondition {
  maxCalls: number;
  windowSeconds: number;
}

export interface RuleConditions {
  paths?: PathCondition;
  commands?: CommandCondition;
  network?: NetworkCondition;
  rateLimit?: RateLimitCondition;
  paramPatterns?: Record<string, string>; // Parameter name -> Regex pattern to detect suspicious content
}

export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  toolPattern: string; // Tool name or glob pattern e.g. "execute_command", "write_*", "*"
  action: PolicyAction;
  riskLevel: RiskLevel;
  conditions?: RuleConditions;
  reason?: string;
}

export interface SandboxPolicyConfig {
  driver: 'auto' | 'docker' | 'process';
  maxExecutionTimeMs: number;
  maxMemoryMb: number;
  allowNetwork: boolean;
  envWhitelist: string[];
  isolatedWorkspaceDir?: string;
}

export interface SecurityPolicy {
  name: string;
  version: string;
  description?: string;
  defaultAction: PolicyAction;
  sandbox: SandboxPolicyConfig;
  rules: PolicyRule[];
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  action: PolicyAction;
  riskLevel: RiskLevel;
  riskScore: number; // 0 to 100
  matchedRule: PolicyRule | null;
  reasons: string[];
  requiresApproval: boolean;
  shouldSandbox: boolean;
}
