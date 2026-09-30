import { z } from 'zod';

export const PathConditionSchema = z.object({
  allowed: z.array(z.string()).optional(),
  denied: z.array(z.string()).optional(),
  allowSubdirectories: z.boolean().default(true).optional(),
});

export const CommandConditionSchema = z.object({
  allowed: z.array(z.string()).optional(),
  denied: z.array(z.string()).optional(),
  denyPatterns: z.array(z.string()).optional(),
});

export const NetworkConditionSchema = z.object({
  allowOutbound: z.boolean().optional(),
  allowedHosts: z.array(z.string()).optional(),
  deniedHosts: z.array(z.string()).optional(),
});

export const RateLimitConditionSchema = z.object({
  maxCalls: z.number().int().positive(),
  windowSeconds: z.number().int().positive(),
});

export const RuleConditionsSchema = z.object({
  paths: PathConditionSchema.optional(),
  commands: CommandConditionSchema.optional(),
  network: NetworkConditionSchema.optional(),
  rateLimit: RateLimitConditionSchema.optional(),
  paramPatterns: z.record(z.string(), z.string()).optional(),
});

export const PolicyRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  toolPattern: z.string(),
  action: z.enum(['allow', 'block', 'sandbox', 'require_approval']),
  riskLevel: z.enum(['low', 'medium', 'high', 'critical']),
  conditions: RuleConditionsSchema.optional(),
  reason: z.string().optional(),
});

export const SandboxPolicyConfigSchema = z.object({
  driver: z.enum(['auto', 'docker', 'process']).default('auto'),
  maxExecutionTimeMs: z.number().int().positive().default(30000),
  maxMemoryMb: z.number().int().positive().default(512),
  allowNetwork: z.boolean().default(false),
  envWhitelist: z.array(z.string()).default(['PATH', 'NODE_ENV', 'LANG', 'LC_ALL']),
  isolatedWorkspaceDir: z.string().optional(),
});

export const SecurityPolicySchema = z.object({
  name: z.string(),
  version: z.string(),
  description: z.string().optional(),
  defaultAction: z.enum(['allow', 'block', 'sandbox', 'require_approval']).default('require_approval'),
  sandbox: SandboxPolicyConfigSchema.default({
    driver: 'auto',
    maxExecutionTimeMs: 30000,
    maxMemoryMb: 512,
    allowNetwork: false,
    envWhitelist: ['PATH', 'NODE_ENV', 'LANG', 'LC_ALL'],
  }),
  rules: z.array(PolicyRuleSchema),
});

export type ValidatedSecurityPolicy = z.infer<typeof SecurityPolicySchema>;
