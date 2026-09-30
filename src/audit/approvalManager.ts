import { EventEmitter } from 'node:events';
import { v4 as uuidv4 } from 'uuid';
import { PendingApproval } from './types.js';
import { PolicyEvaluationResult } from '../policy/types.js';

interface InternalPendingApproval extends PendingApproval {
  timer: NodeJS.Timeout;
  resolvePromise: (value: { approved: boolean; note?: string }) => void;
}

export class ApprovalManager extends EventEmitter {
  private pendingApprovals: Map<string, InternalPendingApproval> = new Map();
  private defaultTimeoutMs: number;

  constructor(defaultTimeoutMs = 60000) {
    super();
    this.defaultTimeoutMs = defaultTimeoutMs;
  }

  /**
   * Request human approval for a risky tool call
   */
  public requestApproval(
    toolName: string,
    args: Record<string, unknown>,
    evaluation: PolicyEvaluationResult
  ): Promise<{ approved: boolean; note?: string }> {
    const id = uuidv4().slice(0, 8);
    const expiresAt = Date.now() + this.defaultTimeoutMs;

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pendingApprovals.delete(id);
        this.emit('approval_timeout', { id, toolName });
        resolve({ approved: false, note: 'Approval request timed out.' });
      }, this.defaultTimeoutMs);

      const approvalItem: InternalPendingApproval = {
        id,
        timestamp: new Date().toISOString(),
        toolName,
        args,
        riskScore: evaluation.riskScore,
        riskLevel: evaluation.riskLevel,
        reasons: evaluation.reasons,
        expiresAt,
        timer,
        resolvePromise: resolve,
      };

      this.pendingApprovals.set(id, approvalItem);

      // Emit event for connected WebSocket clients & dashboard
      this.emit('approval_requested', {
        id: approvalItem.id,
        timestamp: approvalItem.timestamp,
        toolName: approvalItem.toolName,
        args: approvalItem.args,
        riskScore: approvalItem.riskScore,
        riskLevel: approvalItem.riskLevel,
        reasons: approvalItem.reasons,
        expiresAt: approvalItem.expiresAt,
      });
    });
  }

  /**
   * Resolve an approval request from UI or CLI
   */
  public resolveApproval(id: string, approved: boolean, note?: string): boolean {
    const pending = this.pendingApprovals.get(id);
    if (!pending) {
      return false;
    }

    clearTimeout(pending.timer);
    this.pendingApprovals.delete(id);

    pending.resolvePromise({ approved, note });
    this.emit('approval_resolved', { id, approved, note, toolName: pending.toolName });
    return true;
  }

  /**
   * List all currently pending approvals
   */
  public getPendingList(): PendingApproval[] {
    return Array.from(this.pendingApprovals.values()).map(
      ({ id, timestamp, toolName, args, riskScore, riskLevel, reasons, expiresAt }) => ({
        id,
        timestamp,
        toolName,
        args,
        riskScore,
        riskLevel,
        reasons,
        expiresAt,
      })
    );
  }
}
