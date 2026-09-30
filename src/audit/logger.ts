import { EventEmitter } from 'node:events';
import chalk from 'chalk';
import { AuditLogEntry, ToolExecutionStatus } from './types.js';

export interface AuditMetrics {
  totalRequests: number;
  allowedCount: number;
  sandboxedCount: number;
  blockedCount: number;
  approvedCount: number;
  rejectedCount: number;
  avgLatencyMs: number;
  criticalEventsCount: number;
}

export class AuditLogger extends EventEmitter {
  private logs: AuditLogEntry[] = [];
  private maxLogs: number;
  private verboseCli: boolean;

  constructor(maxLogs = 500, verboseCli = true) {
    super();
    this.maxLogs = maxLogs;
    this.verboseCli = verboseCli;
  }

  public record(entry: AuditLogEntry): void {
    this.logs.unshift(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.pop();
    }

    if (this.verboseCli) {
      this.printCliLog(entry);
    }

    this.emit('log_entry', entry);
  }

  public getRecentLogs(limit = 50): AuditLogEntry[] {
    return this.logs.slice(0, limit);
  }

  public getMetrics(): AuditMetrics {
    const total = this.logs.length;
    let allowedCount = 0;
    let sandboxedCount = 0;
    let blockedCount = 0;
    let approvedCount = 0;
    let rejectedCount = 0;
    let totalLatency = 0;
    let criticalEventsCount = 0;

    for (const log of this.logs) {
      totalLatency += log.latencyMs;
      if (log.status === 'allowed') allowedCount++;
      else if (log.status === 'sandboxed') sandboxedCount++;
      else if (log.status === 'blocked') blockedCount++;
      else if (log.status === 'approved') approvedCount++;
      else if (log.status === 'rejected') rejectedCount++;

      if (log.riskLevel === 'critical' || log.riskLevel === 'high') {
        criticalEventsCount++;
      }
    }

    return {
      totalRequests: total,
      allowedCount,
      sandboxedCount,
      blockedCount,
      approvedCount,
      rejectedCount,
      avgLatencyMs: total > 0 ? Math.round(totalLatency / total) : 0,
      criticalEventsCount,
    };
  }

  private printCliLog(entry: AuditLogEntry): void {
    const time = new Date(entry.timestamp).toLocaleTimeString();
    const riskBadge = this.formatRiskBadge(entry.riskLevel, entry.riskScore);
    const statusBadge = this.formatStatusBadge(entry.status);

    const logLine = `[${chalk.gray(time)}] ${statusBadge} ${chalk.bold(entry.toolName)} ${riskBadge} (${entry.latencyMs.toFixed(1)}ms)`;
    console.error(logLine);

    if (entry.status === 'blocked' || entry.status === 'rejected') {
      console.error(chalk.red(`  ↳ Reason: ${entry.reasons.join(', ')}`));
    } else if (entry.sandboxed) {
      console.error(chalk.cyan(`  ↳ Isolated in ${entry.sandboxDriver || 'sandbox'}`));
    }
  }

  private formatRiskBadge(level: string, score: number): string {
    switch (level) {
      case 'critical':
        return chalk.bgRed.black(` CRITICAL ${score} `);
      case 'high':
        return chalk.red(`[High:${score}]`);
      case 'medium':
        return chalk.yellow(`[Med:${score}]`);
      default:
        return chalk.green(`[Low:${score}]`);
    }
  }

  private formatStatusBadge(status: ToolExecutionStatus): string {
    switch (status) {
      case 'allowed':
        return chalk.green('✓ ALLOW');
      case 'sandboxed':
        return chalk.cyan('🛡 SANDBOX');
      case 'blocked':
        return chalk.red('✗ BLOCKED');
      case 'approved':
        return chalk.greenBright('✔ APPROVED');
      case 'rejected':
        return chalk.redBright('⊘ REJECTED');
      case 'timeout':
        return chalk.yellow('⏱ TIMEOUT');
      default:
        return chalk.magenta(status.toUpperCase());
    }
  }
}
