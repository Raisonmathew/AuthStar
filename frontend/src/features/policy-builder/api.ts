/**
 * Policy Builder API client.
 * All calls go to /api/v1/policy-builder/*
 */

import { api } from '../../lib/api';
import type {
  ActionItem,
  AddConditionRequest,
  AddGroupRequest,
  AddRuleRequest,
  AuditPage,
  CompileResponse,
  ConditionDetail,
  ConditionTypeItem,
  ConfigDetail,
  ConfigSummary,
  CreateActionRequest,
  CreateConfigRequest,
  CreateTemplateRequest,
  DiffResponse,
  GroupDetail,
  PreviewResponse,
  ReorderRequest,
  RuleDetail,
  SimulateRequest,
  SimulateResponse,
  TemplateItem,
  UpdateConditionRequest,
  UpdateConfigRequest,
  UpdateGroupRequest,
  UpdateRuleRequest,
  VersionDetail,
  VersionSummary,
} from './types';

const BASE = '/api/v1/policy-builder';

// ============================================================================
// Templates
// ============================================================================

export const listTemplates = async (): Promise<TemplateItem[]> => {
  const res = await api.get<TemplateItem[]>(`${BASE}/templates`);
  return res.data;
};

export const getTemplate = async (slug: string): Promise<TemplateItem> => {
  const res = await api.get<TemplateItem>(`${BASE}/templates/${slug}`);
  return res.data;
};

export const listSupportedConditions = async (slug: string): Promise<ConditionTypeItem[]> => {
  const res = await api.get<ConditionTypeItem[]>(`${BASE}/templates/${slug}/conditions`);
  return res.data;
};

export const createTemplate = async (req: CreateTemplateRequest): Promise<TemplateItem> => {
  const res = await api.post<TemplateItem>(`${BASE}/templates`, req);
  return res.data;
};

// ============================================================================
// Condition Types catalog
// ============================================================================

export const listConditionTypes = async (): Promise<ConditionTypeItem[]> => {
  const res = await api.get<ConditionTypeItem[]>(`${BASE}/condition-types`);
  return res.data;
};

// ============================================================================
// Actions
// ============================================================================

export const listActions = async (): Promise<ActionItem[]> => {
  const res = await api.get<ActionItem[]>(`${BASE}/actions`);
  return res.data;
};

export const createAction = async (req: CreateActionRequest): Promise<ActionItem> => {
  const res = await api.post<ActionItem>(`${BASE}/actions`, req);
  return res.data;
};

// ============================================================================
// Configs
// ============================================================================

export const listConfigs = async (): Promise<ConfigSummary[]> => {
  const res = await api.get<ConfigSummary[]>(`${BASE}/configs`);
  return res.data;
};

export const createConfig = async (req: CreateConfigRequest): Promise<ConfigDetail> => {
  const res = await api.post<ConfigDetail>(`${BASE}/configs`, req);
  return res.data;
};

export const getConfig = async (id: string): Promise<ConfigDetail> => {
  const res = await api.get<ConfigDetail>(`${BASE}/configs/${id}`);
  return res.data;
};

export const updateConfig = async (id: string, req: UpdateConfigRequest): Promise<void> => {
  await api.put(`${BASE}/configs/${id}`, req);
};

export const archiveConfig = async (id: string): Promise<void> => {
  await api.delete(`${BASE}/configs/${id}`);
};

// ============================================================================
// Rule Groups
// ============================================================================

export const addGroup = async (configId: string, req: AddGroupRequest): Promise<GroupDetail> => {
  const res = await api.post<GroupDetail>(`${BASE}/configs/${configId}/groups`, req);
  return res.data;
};

export const updateGroup = async (
  configId: string,
  groupId: string,
  req: UpdateGroupRequest
): Promise<void> => {
  await api.put(`${BASE}/configs/${configId}/groups/${groupId}`, req);
};

export const removeGroup = async (configId: string, groupId: string): Promise<void> => {
  await api.delete(`${BASE}/configs/${configId}/groups/${groupId}`);
};

export const reorderGroups = async (configId: string, order: string[]): Promise<void> => {
  const req: ReorderRequest = { order };
  await api.post(`${BASE}/configs/${configId}/groups/reorder`, req);
};

// ============================================================================
// Rules
// ============================================================================

export const addRule = async (
  configId: string,
  groupId: string,
  req: AddRuleRequest
): Promise<RuleDetail> => {
  const res = await api.post<RuleDetail>(
    `${BASE}/configs/${configId}/groups/${groupId}/rules`,
    req
  );
  return res.data;
};

export const updateRule = async (
  configId: string,
  groupId: string,
  ruleId: string,
  req: UpdateRuleRequest
): Promise<void> => {
  await api.put(`${BASE}/configs/${configId}/groups/${groupId}/rules/${ruleId}`, req);
};

export const removeRule = async (
  configId: string,
  groupId: string,
  ruleId: string
): Promise<void> => {
  await api.delete(`${BASE}/configs/${configId}/groups/${groupId}/rules/${ruleId}`);
};

export const reorderRules = async (
  configId: string,
  groupId: string,
  order: string[]
): Promise<void> => {
  const req: ReorderRequest = { order };
  await api.post(`${BASE}/configs/${configId}/groups/${groupId}/rules/reorder`, req);
};

// ============================================================================
// Conditions
// ============================================================================

export const addCondition = async (
  configId: string,
  groupId: string,
  ruleId: string,
  req: AddConditionRequest
): Promise<ConditionDetail> => {
  const res = await api.post<ConditionDetail>(
    `${BASE}/configs/${configId}/groups/${groupId}/rules/${ruleId}/conditions`,
    req
  );
  return res.data;
};

export const updateCondition = async (
  configId: string,
  groupId: string,
  ruleId: string,
  condId: string,
  req: UpdateConditionRequest
): Promise<void> => {
  await api.put(
    `${BASE}/configs/${configId}/groups/${groupId}/rules/${ruleId}/conditions/${condId}`,
    req
  );
};

export const removeCondition = async (
  configId: string,
  groupId: string,
  ruleId: string,
  condId: string
): Promise<void> => {
  await api.delete(
    `${BASE}/configs/${configId}/groups/${groupId}/rules/${ruleId}/conditions/${condId}`
  );
};

// ============================================================================
// Compile / Preview / Simulate / Activate
// ============================================================================

export const previewConfig = async (id: string): Promise<PreviewResponse> => {
  const res = await api.get<PreviewResponse>(`${BASE}/configs/${id}/preview`);
  return res.data;
};

export const simulateConfig = async (
  id: string,
  req: SimulateRequest
): Promise<SimulateResponse> => {
  const res = await api.post<SimulateResponse>(`${BASE}/configs/${id}/simulate`, req);
  return res.data;
};

export const compileConfig = async (id: string): Promise<CompileResponse> => {
  const res = await api.post<CompileResponse>(`${BASE}/configs/${id}/compile`);
  return res.data;
};

export const activateConfig = async (id: string): Promise<void> => {
  await api.post(`${BASE}/configs/${id}/activate`);
};

// ============================================================================
// Versions
// ============================================================================

export const listVersions = async (id: string): Promise<VersionSummary[]> => {
  const res = await api.get<VersionSummary[]>(`${BASE}/configs/${id}/versions`);
  return res.data;
};

export const getVersion = async (id: string, versionId: string): Promise<VersionDetail> => {
  const res = await api.get<VersionDetail>(`${BASE}/configs/${id}/versions/${versionId}`);
  return res.data;
};

export const rollbackVersion = async (id: string, versionId: string): Promise<void> => {
  await api.post(`${BASE}/configs/${id}/versions/${versionId}/rollback`);
};

export const diffVersions = async (
  id: string,
  versionId: string,
  compareToId?: string
): Promise<DiffResponse> => {
  const res = await api.post<DiffResponse>(
    `${BASE}/configs/${id}/versions/${versionId}/diff`,
    compareToId ? { compare_to: compareToId } : {}
  );
  return res.data;
};

export const exportVersionAst = async (
  id: string,
  versionId: string
): Promise<Record<string, unknown>> => {
  const res = await api.get<Record<string, unknown>>(
    `${BASE}/configs/${id}/versions/${versionId}/export-ast`
  );
  return res.data;
};

// ============================================================================
// Audit
// ============================================================================

export const getConfigAudit = async (
  id: string,
  params?: { limit?: number; before?: string }
): Promise<AuditPage> => {
  const res = await api.get<AuditPage>(`${BASE}/configs/${id}/audit`, { params });
  return res.data;
};

export const getTenantAudit = async (params?: {
  limit?: number;
  before?: string;
  action_key?: string;
}): Promise<AuditPage> => {
  const res = await api.get<AuditPage>(`${BASE}/audit`, { params });
  return res.data;
};