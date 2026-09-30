import path from 'node:path';
import os from 'node:os';
import {
  SecurityPolicy,
  PolicyRule,
  PolicyEvaluationResult,
  PolicyAction,
  RiskLevel,
} from './types.js';

interface RateLimitTracker {
  timestamps: number[];
}

export class PolicyEngine {
  private policy: SecurityPolicy;
  private rateLimits: Map<string, RateLimitTracker> = new Map();
  private homeDir: string;
  private workspaceDir: string;

  constructor(policy: SecurityPolicy, workspaceDir?: string) {
    this.policy = policy;
    this.homeDir = os.homedir();
    this.workspaceDir = path.resolve(workspaceDir || process.cwd());
  }

  public updatePolicy(newPolicy: SecurityPolicy): void {
    this.policy = newPolicy;
  }

  public getPolicy(): SecurityPolicy {
    return this.policy;
  }

  /**
   * Evaluates an incoming MCP tool call against policy rules.
   */
  public evaluate(toolName: string, args: Record<string, unknown> = {}): PolicyEvaluationResult {
    const reasons: string[] = [];

    // 1. Evaluate specific rules in descending priority
    for (const rule of this.policy.rules) {
      if (!this.matchesToolPattern(toolName, rule.toolPattern)) {
        continue;
      }

      // Check path conditions if applicable
      const pathViolation = this.checkPathConditions(rule, args);
      if (pathViolation.violated) {
        reasons.push(pathViolation.reason || `Path restriction violated under rule '${rule.name}'`);
        return this.createResult(rule.action, rule.riskLevel, rule, reasons);
      }

      // Check command conditions if applicable
      const commandViolation = this.checkCommandConditions(rule, args);
      if (commandViolation.violated) {
        reasons.push(commandViolation.reason || `Command pattern matched blocked signature under rule '${rule.name}'`);
        return this.createResult(rule.action, rule.riskLevel, rule, reasons);
      }

      // Check rate limit conditions if applicable
      if (rule.conditions?.rateLimit) {
        const rateLimitExceeded = this.checkRateLimit(rule.id, rule.conditions.rateLimit.maxCalls, rule.conditions.rateLimit.windowSeconds);
        if (rateLimitExceeded) {
          reasons.push(`Rate limit exceeded for rule '${rule.name}': max ${rule.conditions.rateLimit.maxCalls} calls per ${rule.conditions.rateLimit.windowSeconds}s.`);
          return this.createResult('block', 'high', rule, reasons);
        }
      }

      // If the rule specifically guarded on conditions (like path/command denial patterns)
      // and neither condition matched, then do not fire this rule yet (continue to next rule)
      if (rule.conditions?.paths || rule.conditions?.commands) {
        if (pathViolation.conditionMatched || commandViolation.conditionMatched) {
          reasons.push(rule.reason || `Rule '${rule.name}' matched execution conditions.`);
          return this.createResult(rule.action, rule.riskLevel, rule, reasons);
        }
        continue;
      }

      // Unconditional rule match (e.g. general read tool allow or general shell sandbox)
      reasons.push(rule.reason || `Rule '${rule.name}' matched tool pattern '${rule.toolPattern}'.`);
      return this.createResult(rule.action, rule.riskLevel, rule, reasons);
    }

    // 2. Fall back to default policy action
    reasons.push(`No explicit rule matched tool '${toolName}'. Applying default action '${this.policy.defaultAction}'.`);
    const defaultRisk: RiskLevel = this.policy.defaultAction === 'allow' ? 'low' : 'high';
    return this.createResult(this.policy.defaultAction, defaultRisk, null, reasons);
  }

  /**
   * Glob and pattern matching helper for tool names
   */
  public matchesToolPattern(toolName: string, pattern: string): boolean {
    if (pattern === '*' || pattern === toolName) return true;

    try {
      let res = pattern
        .replace(/\*\*/g, '__DSTAR__')
        .replace(/\*/g, '__SSTAR__')
        .replace(/\?/g, '__QMARK__');

      // Escape regex special chars: [ ] { } . + ^ $ \
      res = res.replace(/[.+^${}[\]\\]/g, '\\$&');

      res = res.replace(/__DSTAR__/g, '.*');
      res = res.replace(/__SSTAR__/g, '.*');
      res = res.replace(/__QMARK__/g, '.');

      const regex = new RegExp(`^${res}$`, 'i');
      return regex.test(toolName);
    } catch {
      return toolName.toLowerCase().includes(pattern.toLowerCase().replace(/\*/g, ''));
    }
  }

  /**
   * Inspects arguments for file/directory paths and checks against deny/allow lists
   */
  private checkPathConditions(
    rule: PolicyRule,
    args: Record<string, unknown>
  ): { violated: boolean; conditionMatched: boolean; reason?: string } {
    if (!rule.conditions?.paths) {
      return { violated: false, conditionMatched: false };
    }

    const pathsInArgs = this.extractPathsFromArgs(args);
    if (pathsInArgs.length === 0) {
      return { violated: false, conditionMatched: false };
    }

    const { denied = [], allowed = [] } = rule.conditions.paths;

    for (const rawPath of pathsInArgs) {
      const normalized = this.normalizePath(rawPath);

      // Check denied paths
      for (const denyPattern of denied) {
        if (this.pathMatches(normalized, denyPattern)) {
          return {
            violated: true,
            conditionMatched: true,
            reason: `Target path '${rawPath}' matches denied pattern '${denyPattern}'`,
          };
        }
      }

      // Check allowed paths if defined
      if (allowed.length > 0) {
        const isAllowed = allowed.some((allowPattern) => this.pathMatches(normalized, allowPattern));
        if (!isAllowed) {
          return {
            violated: true,
            conditionMatched: true,
            reason: `Target path '${rawPath}' is not in the allowed paths list`,
          };
        }
      }
    }

    return { violated: false, conditionMatched: false };
  }

  /**
   * Inspects arguments for shell commands and checks against patterns
   */
  private checkCommandConditions(
    rule: PolicyRule,
    args: Record<string, unknown>
  ): { violated: boolean; conditionMatched: boolean; reason?: string } {
    if (!rule.conditions?.commands) {
      return { violated: false, conditionMatched: false };
    }

    const commands = this.extractCommandsFromArgs(args);
    if (commands.length === 0) {
      return { violated: false, conditionMatched: false };
    }

    const { denyPatterns = [], denied = [] } = rule.conditions.commands;

    for (const cmd of commands) {
      // Check exact denied commands
      for (const deniedCmd of denied) {
        if (cmd.trim() === deniedCmd.trim()) {
          return {
            violated: true,
            conditionMatched: true,
            reason: `Command matched explicitly denied command '${deniedCmd}'`,
          };
        }
      }

      // Check regex deny patterns
      for (const pattern of denyPatterns) {
        try {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(cmd)) {
            const reasonText = rule.reason
              ? `${rule.reason} (Matched signature: ${pattern})`
              : `Command '${cmd.slice(0, 60)}...' matched blocked security pattern: ${pattern}`;
            return {
              violated: true,
              conditionMatched: true,
              reason: reasonText,
            };
          }
        } catch {
          if (cmd.includes(pattern)) {
            return {
              violated: true,
              conditionMatched: true,
              reason: `Command contains blocked substring '${pattern}'`,
            };
          }
        }
      }
    }

    return { violated: false, conditionMatched: false };
  }

  private checkRateLimit(ruleId: string, maxCalls: number, windowSeconds: number): boolean {
    const now = Date.now();
    const windowMs = windowSeconds * 1000;

    let tracker = this.rateLimits.get(ruleId);
    if (!tracker) {
      tracker = { timestamps: [] };
      this.rateLimits.set(ruleId, tracker);
    }

    tracker.timestamps = tracker.timestamps.filter((ts) => now - ts < windowMs);

    if (tracker.timestamps.length >= maxCalls) {
      return true;
    }

    tracker.timestamps.push(now);
    return false;
  }

  private extractPathsFromArgs(args: Record<string, unknown>): string[] {
    const paths: string[] = [];
    const pathKeys = [
      'path',
      'targetFile',
      'target_file',
      'file',
      'filepath',
      'filePath',
      'AbsolutePath',
      'directory',
      'dir',
      'source',
      'destination',
      'dest',
    ];

    for (const [key, value] of Object.entries(args)) {
      if (pathKeys.includes(key) && typeof value === 'string') {
        paths.push(value);
      } else if (typeof value === 'object' && value !== null) {
        paths.push(...this.extractPathsFromArgs(value as Record<string, unknown>));
      }
    }

    return paths;
  }

  private extractCommandsFromArgs(args: Record<string, unknown>): string[] {
    const commands: string[] = [];
    const cmdKeys = ['command', 'cmd', 'CommandLine', 'commandLine', 'script', 'code', 'eval'];

    for (const [key, value] of Object.entries(args)) {
      if (cmdKeys.includes(key) && typeof value === 'string') {
        commands.push(value);
      } else if (typeof value === 'object' && value !== null) {
        commands.push(...this.extractCommandsFromArgs(value as Record<string, unknown>));
      }
    }

    return commands;
  }

  private normalizePath(rawPath: string): string {
    let resolved = rawPath;
    if (resolved.startsWith('~')) {
      resolved = path.join(this.homeDir, resolved.slice(1));
    }
    if (!path.isAbsolute(resolved)) {
      resolved = path.resolve(this.workspaceDir, resolved);
    }
    return path.normalize(resolved);
  }

  private pathMatches(targetPath: string, pattern: string): boolean {
    let normPattern = pattern;
    if (normPattern.startsWith('~')) {
      normPattern = path.join(this.homeDir, normPattern.slice(1));
    }

    if (normPattern.includes('*')) {
      let res = normPattern
        .replace(/\*\*/g, '__DSTAR__')
        .replace(/\*/g, '__SSTAR__');

      res = res.replace(/[.+^${}[\]\\]/g, '\\$&');

      res = res.replace(/__DSTAR__/g, '.*');
      res = res.replace(/__SSTAR__/g, '[^/]*');

      try {
        const regex = new RegExp(`^${res}$`, 'i');
        if (regex.test(targetPath)) return true;
        const regexAnywhere = new RegExp(`${res}$`, 'i');
        return regexAnywhere.test(targetPath);
      } catch {
        return targetPath.includes(pattern.replace(/\*/g, ''));
      }
    }

    const normTarget = path.normalize(targetPath);
    const resolvedPattern = path.normalize(normPattern);

    return normTarget === resolvedPattern || normTarget.startsWith(resolvedPattern + path.sep);
  }

  private createResult(
    action: PolicyAction,
    riskLevel: RiskLevel,
    matchedRule: PolicyRule | null,
    reasons: string[]
  ): PolicyEvaluationResult {
    const riskScoreMap: Record<RiskLevel, number> = {
      low: 15,
      medium: 50,
      high: 80,
      critical: 98,
    };

    return {
      allowed: action === 'allow' || action === 'sandbox',
      action,
      riskLevel,
      riskScore: riskScoreMap[riskLevel],
      matchedRule,
      reasons,
      requiresApproval: action === 'require_approval',
      shouldSandbox: action === 'sandbox',
    };
  }
}
