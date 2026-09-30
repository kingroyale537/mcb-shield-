import { PolicyAction, RiskLevel } from '../policy/types.js';

export type ToolExecutionStatus =
  | 'allowed'
  | 'sandboxed'
  | 'blocked'
  | 'approved'
  | 'rejected'
  | 'timeout'
  | 'error';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  toolName: string;
  args: Record<string, unknown>;
  action: PolicyAction;
  riskLevel: RiskLevel;
  riskScore: number;
  ruleId?: string;
  reasons: string[];
  status: ToolExecutionStatus;
  latencyMs: number;
  sandboxed: boolean;
  sandboxDriver?: string;
  outputPreview?: string;
  error?: string;
}

export interface PendingApproval {
  id: string;
  timestamp: string;
  toolName: string;
  args: Record<string, unknown>;
  riskScore: number;
  riskLevel: RiskLevel;
  reasons: string[];
  expiresAt: number;
}
