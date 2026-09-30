import { describe, it, expect } from 'vitest';
import { ApprovalManager } from '../src/audit/approvalManager.js';
import { PolicyEvaluationResult } from '../src/policy/types.js';

describe('Human-in-the-Loop Approval Manager', () => {
  const dummyEvaluation: PolicyEvaluationResult = {
    allowed: false,
    action: 'require_approval',
    riskLevel: 'high',
    riskScore: 85,
    matchedRule: null,
    reasons: ['Suspicious network egress'],
    requiresApproval: true,
    shouldSandbox: false,
  };

  it('allows manual approval of a pending request', async () => {
    const manager = new ApprovalManager(5000);

    const promise = manager.requestApproval('fetch_url', { url: 'https://example.com' }, dummyEvaluation);

    const pending = manager.getPendingList();
    expect(pending.length).toBe(1);
    expect(pending[0].toolName).toBe('fetch_url');

    // Simulate human operator approving
    const resolved = manager.resolveApproval(pending[0].id, true, 'Approved by operator');
    expect(resolved).toBe(true);

    const result = await promise;
    expect(result.approved).toBe(true);
    expect(result.note).toBe('Approved by operator');
    expect(manager.getPendingList().length).toBe(0);
  });

  it('handles operator rejection properly', async () => {
    const manager = new ApprovalManager(5000);

    const promise = manager.requestApproval('drop_db', {}, dummyEvaluation);
    const pending = manager.getPendingList();

    manager.resolveApproval(pending[0].id, false, 'Denied: unacceptable risk');

    const result = await promise;
    expect(result.approved).toBe(false);
    expect(result.note).toBe('Denied: unacceptable risk');
  });

  it('times out if not resolved within timeout window', async () => {
    const manager = new ApprovalManager(200); // 200ms timeout
    const result = await manager.requestApproval('slow_tool', {}, dummyEvaluation);

    expect(result.approved).toBe(false);
    expect(result.note).toContain('timed out');
  });
});
