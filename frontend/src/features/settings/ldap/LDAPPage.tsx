import React, { useEffect, useState } from 'react';
import { api } from '../../../lib/api';
import { toast } from 'sonner';

interface LDAPConnection {
    id: string;
    name: string;
    host: string;
    port: number;
    use_ssl: boolean;
    start_tls: boolean;
    bind_dn: string;
    base_dn: string;
    user_search_filter: string;
    attr_map_email: string;
    attr_map_name: string;
    enabled: boolean;
    last_sync_at?: string;
    last_full_sync_at?: string;
    last_delta_sync_at?: string;
    sync_status?: 'idle' | 'syncing' | 'error';
    vendor: string;
    edit_mode: string;
    sync_interval_minutes: number;
    connection_timeout_secs: number;
    page_size: number;
    uuid_attr: string;
    username_attr: string;
    groups_dn?: string;
    group_name_attr: string;
    group_object_class: string;
    group_membership_attr: string;
    group_membership_type: string;
    trust_email: boolean;
    skip_tls_verify: boolean;
    read_timeout_secs: number;
    failover_hosts: string;
    search_scope: string;
}

interface SyncRun {
    id: string;
    connection_id: string;
    started_at: string;
    finished_at?: string;
    status: 'running' | 'completed' | 'failed';
    users_found: number;
    users_created: number;
    users_updated: number;
    users_disabled: number;
    error_message?: string;
}

interface LdapMapper {
    id: string;
    connection_id: string;
    name: string;
    mapper_type: string;
    config: Record<string, unknown>;
    enabled: boolean;
}

interface TestResult {
    success: boolean;
    message: string;
    naming_contexts?: string[];
    ldap_versions?: string[];
}

const VENDOR_PRESETS: Record<string, {
    port: number; ssl: boolean; filter: string; emailAttr: string; nameAttr: string;
    uuidAttr: string; usernameAttr: string;
    groupObjectClass: string; groupMemberAttr: string;
}> = {
    ad: {
        port: 389, ssl: false,
        filter: '(&(objectClass=user)(!(objectClass=computer)))',
        emailAttr: 'mail', nameAttr: 'cn',
        uuidAttr: 'objectGUID', usernameAttr: 'sAMAccountName',
        groupObjectClass: 'group', groupMemberAttr: 'member',
    },
    openldap: {
        port: 389, ssl: false,
        filter: '(objectClass=inetOrgPerson)',
        emailAttr: 'mail', nameAttr: 'cn',
        uuidAttr: 'entryUUID', usernameAttr: 'uid',
        groupObjectClass: 'groupOfNames', groupMemberAttr: 'member',
    },
    rhds: {
        port: 389, ssl: false,
        filter: '(objectClass=person)',
        emailAttr: 'mail', nameAttr: 'cn',
        uuidAttr: 'nsUniqueId', usernameAttr: 'uid',
        groupObjectClass: 'groupOfNames', groupMemberAttr: 'member',
    },
    other: {
        port: 389, ssl: false,
        filter: '(objectClass=person)',
        emailAttr: 'mail', nameAttr: 'cn',
        uuidAttr: 'entryUUID', usernameAttr: 'uid',
        groupObjectClass: 'groupOfNames', groupMemberAttr: 'member',
    },
};

const VENDOR_LABELS: Record<string, string> = {
    ad: 'Active Directory',
    openldap: 'OpenLDAP',
    rhds: 'Red Hat DS / 389-DS',
    other: 'Other',
};

const DEFAULT_FILTER = '(objectClass=person)';

type ModalTab = 'basic' | 'advanced' | 'mappers';
type DetailTab = 'none' | 'syncHistory' | 'mappers';

export default function LDAPPage() {
    const [connections, setConnections] = useState<LDAPConnection[]>([]);
    const [loading, setLoading] = useState(true);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [modalTab, setModalTab] = useState<ModalTab>('basic');
    const [editingConn, setEditingConn] = useState<LDAPConnection | null>(null);
    const [testing, setTesting] = useState<string | null>(null);
    const [testResult, setTestResult] = useState<TestResult | null>(null);
    const [syncing, setSyncing] = useState<string | null>(null);
    const [detailConn, setDetailConn] = useState<string | null>(null);
    const [detailTab, setDetailTab] = useState<DetailTab>('syncHistory');
    const [syncRuns, setSyncRuns] = useState<SyncRun[]>([]);
    const [mappers, setMappers] = useState<LdapMapper[]>([]);
    const [loadingDetail, setLoadingDetail] = useState(false);

    // Mapper create form
    const [mapperName, setMapperName] = useState('');
    const [mapperType, setMapperType] = useState('user-attribute');
    const [mapperLdapAttr, setMapperLdapAttr] = useState('');
    const [mapperUserAttr, setMapperUserAttr] = useState('');
    const [savingMapper, setSavingMapper] = useState(false);

    // Connection form state
    const [name, setName] = useState('');
    const [host, setHost] = useState('');
    const [port, setPort] = useState(389);
    const [useSsl, setUseSsl] = useState(false);
    const [startTls, setStartTls] = useState(false);
    const [bindDn, setBindDn] = useState('');
    const [bindPassword, setBindPassword] = useState('');
    const [baseDn, setBaseDn] = useState('');
    const [userSearchFilter, setUserSearchFilter] = useState(DEFAULT_FILTER);
    const [attrEmail, setAttrEmail] = useState('mail');
    const [attrName, setAttrName] = useState('cn');
    const [vendor, setVendor] = useState('other');
    const [editMode, setEditMode] = useState('READ_ONLY');
    const [syncInterval, setSyncInterval] = useState(0);
    const [connTimeout, setConnTimeout] = useState(10);
    const [readTimeout, setReadTimeout] = useState(30);
    const [pageSize, setPageSize] = useState(100);
    const [uuidAttr, setUuidAttr] = useState('entryUUID');
    const [usernameAttr, setUsernameAttr] = useState('uid');
    const [groupsDn, setGroupsDn] = useState('');
    const [groupNameAttr, setGroupNameAttr] = useState('cn');
    const [groupObjectClass, setGroupObjectClass] = useState('groupOfNames');
    const [groupMemberAttr, setGroupMemberAttr] = useState('member');
    const [groupMemberType, setGroupMemberType] = useState('DN');
    const [skipTlsVerify, setSkipTlsVerify] = useState(false);
    const [failoverHosts, setFailoverHosts] = useState('');
    const [searchScope, setSearchScope] = useState('subtree');
    const [saving, setSaving] = useState(false);

    useEffect(() => { fetchConnections(); }, []);

    const fetchConnections = async () => {
        setLoading(true);
        try {
            const res = await api.get<LDAPConnection[]>('/api/admin/v1/ldap');
            setConnections(res.data);
        } catch {
            toast.error('Failed to load LDAP connections');
        } finally {
            setLoading(false);
        }
    };

    const applyVendorPreset = (v: string) => {
        setVendor(v);
        const p = VENDOR_PRESETS[v] || VENDOR_PRESETS.other;
        setPort(p.port);
        setUseSsl(p.ssl);
        setUserSearchFilter(p.filter);
        setAttrEmail(p.emailAttr);
        setAttrName(p.nameAttr);
        setUuidAttr(p.uuidAttr);
        setUsernameAttr(p.usernameAttr);
        setGroupObjectClass(p.groupObjectClass);
        setGroupMemberAttr(p.groupMemberAttr);
    };

    const openNew = () => {
        setEditingConn(null);
        setModalTab('basic');
        setName(''); setHost(''); setPort(389); setUseSsl(false); setStartTls(false);
        setBindDn(''); setBindPassword(''); setBaseDn('');
        setUserSearchFilter(DEFAULT_FILTER); setAttrEmail('mail'); setAttrName('cn');
        setVendor('other'); setEditMode('READ_ONLY'); setSyncInterval(0);
        setConnTimeout(10); setPageSize(100); setReadTimeout(30);
        setUuidAttr('entryUUID'); setUsernameAttr('uid');
        setGroupsDn(''); setGroupNameAttr('cn'); setGroupObjectClass('groupOfNames');
        setGroupMemberAttr('member'); setGroupMemberType('DN');
        setSkipTlsVerify(false);
        setFailoverHosts(''); setSearchScope('subtree');
        setTestResult(null);
        setIsModalOpen(true);
    };

    const openEdit = (c: LDAPConnection) => {
        setEditingConn(c);
        setModalTab('basic');
        setName(c.name); setHost(c.host); setPort(c.port); setUseSsl(c.use_ssl);
        setStartTls(c.start_tls ?? false);
        setBindDn(c.bind_dn); setBindPassword(''); setBaseDn(c.base_dn);
        setUserSearchFilter(c.user_search_filter);
        setAttrEmail(c.attr_map_email); setAttrName(c.attr_map_name);
        setVendor(c.vendor || 'other'); setEditMode(c.edit_mode || 'READ_ONLY');
        setSyncInterval(c.sync_interval_minutes || 0);
        setConnTimeout(c.connection_timeout_secs || 10);
        setReadTimeout(c.read_timeout_secs ?? 30);
        setPageSize(c.page_size || 100);
        setUuidAttr(c.uuid_attr || 'entryUUID');
        setUsernameAttr(c.username_attr || 'uid');
        setGroupsDn(c.groups_dn || '');
        setGroupNameAttr(c.group_name_attr || 'cn');
        setGroupObjectClass(c.group_object_class || 'groupOfNames');
        setGroupMemberAttr(c.group_membership_attr || 'member');
        setGroupMemberType(c.group_membership_type || 'DN');
        setSkipTlsVerify(c.skip_tls_verify ?? false);
        setFailoverHosts(c.failover_hosts ?? '');
        setSearchScope(c.search_scope ?? 'subtree');
        setTestResult(null);
        setIsModalOpen(true);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        const payload = {
            name, host, port, use_ssl: useSsl, start_tls: startTls,
            bind_dn: bindDn,
            ...(bindPassword ? { bind_password: bindPassword } : {}),
            base_dn: baseDn, user_search_filter: userSearchFilter,
            attr_map_email: attrEmail, attr_map_name: attrName,
            vendor, edit_mode: editMode,
            sync_interval_minutes: syncInterval,
            connection_timeout_secs: connTimeout,
            read_timeout_secs: readTimeout,
            page_size: pageSize,
            uuid_attr: uuidAttr,
            username_attr: usernameAttr,
            groups_dn: groupsDn || null,
            group_name_attr: groupNameAttr,
            group_object_class: groupObjectClass,
            group_membership_attr: groupMemberAttr,
            group_membership_type: groupMemberType,
            skip_tls_verify: skipTlsVerify,
            failover_hosts: failoverHosts,
            search_scope: searchScope,
        };
        try {
            if (editingConn) {
                await api.put(`/api/admin/v1/ldap/${editingConn.id}`, payload);
                toast.success('LDAP connection updated');
            } else {
                await api.post('/api/admin/v1/ldap', payload);
                toast.success('LDAP connection created');
            }
            setIsModalOpen(false);
            fetchConnections();
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Save failed');
        } finally {
            setSaving(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Delete this LDAP connection?')) return;
        try {
            await api.delete(`/api/admin/v1/ldap/${id}`);
            toast.success('Connection deleted');
            if (detailConn === id) setDetailConn(null);
            fetchConnections();
        } catch {
            toast.error('Delete failed');
        }
    };

    const handleTest = async (id: string) => {
        setTesting(id);
        setTestResult(null);
        try {
            const res = await api.post<TestResult>(`/api/admin/v1/ldap/${id}/test`);
            setTestResult(res.data);
            if (res.data.success) {
                toast.success('Connection test successful');
            } else {
                toast.error(`Test failed: ${res.data.message}`);
            }
        } catch (err: any) {
            const msg = err.response?.data?.error || err.response?.data?.message || 'Connection test failed';
            toast.error(msg);
            setTestResult({ success: false, message: msg });
        } finally {
            setTesting(null);
        }
    };

    const handleSync = async (id: string) => {
        setSyncing(id);
        try {
            await api.post(`/api/admin/v1/ldap/${id}/sync`);
            toast.success('User sync started');
            fetchConnections();
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Sync failed');
        } finally {
            setSyncing(null);
        }
    };

    const handleToggleEnabled = async (c: LDAPConnection) => {
        try {
            await api.patch(`/api/admin/v1/ldap/${c.id}`, { enabled: !c.enabled });
            fetchConnections();
        } catch {
            toast.error('Failed to update status');
        }
    };

    const openDetail = async (id: string, tab: DetailTab) => {
        setDetailConn(id);
        setDetailTab(tab);
        setLoadingDetail(true);
        try {
            if (tab === 'syncHistory') {
                const res = await api.get<SyncRun[]>(`/api/admin/v1/ldap/${id}/sync-runs`);
                setSyncRuns(res.data);
            } else if (tab === 'mappers') {
                const res = await api.get<LdapMapper[]>(`/api/admin/v1/ldap/${id}/mappers`);
                setMappers(res.data);
            }
        } catch {
            toast.error('Failed to load data');
        } finally {
            setLoadingDetail(false);
        }
    };

    const handleCreateMapper = async (connId: string) => {
        if (!mapperName || !mapperLdapAttr) return;
        setSavingMapper(true);
        try {
            await api.post(`/api/admin/v1/ldap/${connId}/mappers`, {
                name: mapperName,
                mapper_type: mapperType,
                config: mapperType === 'user-attribute'
                    ? { ldap_attr: mapperLdapAttr, user_attr: mapperUserAttr }
                    : { ldap_group_dn: mapperLdapAttr, membership_role: mapperUserAttr },
                enabled: true,
            });
            toast.success('Mapper created');
            setMapperName(''); setMapperLdapAttr(''); setMapperUserAttr('');
            const res = await api.get<LdapMapper[]>(`/api/admin/v1/ldap/${connId}/mappers`);
            setMappers(res.data);
        } catch (err: any) {
            toast.error(err.response?.data?.error || 'Failed to create mapper');
        } finally {
            setSavingMapper(false);
        }
    };

    const handleDeleteMapper = async (connId: string, mapperId: string) => {
        try {
            await api.delete(`/api/admin/v1/ldap/${connId}/mappers/${mapperId}`);
            setMappers(m => m.filter(x => x.id !== mapperId));
            toast.success('Mapper deleted');
        } catch {
            toast.error('Failed to delete mapper');
        }
    };

    const fmtDate = (d?: string) => d ? new Date(d).toLocaleString() : '—';
    const statusDot = (s?: string) => {
        if (s === 'syncing') return 'bg-blue-500/10 text-blue-600';
        if (s === 'error' || s === 'failed') return 'bg-red-500/10 text-red-600';
        return 'bg-green-500/10 text-green-600';
    };

    const INPUT = 'w-full px-3 py-2 bg-background border border-border rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/30';
    const MONO_INPUT = INPUT + ' font-mono';
    const SELECT = INPUT + ' cursor-pointer';

    return (
        <div className="max-w-5xl mx-auto p-6 space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-foreground font-heading">LDAP / Active Directory</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        Connect to an LDAP directory or Active Directory to federate and sync users.
                    </p>
                </div>
                <button onClick={openNew} className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-2 rounded-xl text-sm font-semibold transition-colors">
                    + Add Connection
                </button>
            </div>

            {loading ? (
                <div className="space-y-3">
                    {[1, 2].map(i => <div key={i} className="h-20 bg-muted/30 rounded-xl animate-pulse" />)}
                </div>
            ) : connections.length === 0 ? (
                <div className="border-2 border-dashed border-border rounded-2xl p-12 text-center">
                    <div className="w-12 h-12 bg-muted rounded-full flex items-center justify-center mx-auto mb-4">
                        <svg className="w-6 h-6 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M12 5l7 7-7 7" />
                        </svg>
                    </div>
                    <h3 className="font-semibold text-foreground mb-1">No LDAP connections</h3>
                    <p className="text-sm text-muted-foreground mb-4">Add an LDAP or Active Directory connection to sync users.</p>
                    <button onClick={openNew} className="bg-primary text-primary-foreground px-4 py-2 rounded-xl text-sm font-semibold">Add Connection</button>
                </div>
            ) : (
                <div className="space-y-3">
                    {connections.map(c => (
                        <div key={c.id} className="bg-card border border-border rounded-2xl overflow-hidden">
                            <div className="p-5">
                                <div className="flex items-start justify-between gap-4">
                                    <div className="min-w-0 flex-1">
                                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                                            <span className="font-semibold text-foreground">{c.name}</span>
                                            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${c.enabled ? 'bg-green-500/10 text-green-600' : 'bg-muted text-muted-foreground'}`}>
                                                {c.enabled ? 'Enabled' : 'Disabled'}
                                            </span>
                                            {c.vendor && c.vendor !== 'other' && (
                                                <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground font-medium">
                                                    {VENDOR_LABELS[c.vendor] || c.vendor}
                                                </span>
                                            )}
                                            {c.sync_status === 'syncing' && (
                                                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-600 font-medium animate-pulse">Syncing…</span>
                                            )}
                                            {c.sync_status === 'error' && (
                                                <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-600 font-medium">Sync error</span>
                                            )}
                                            {c.edit_mode && c.edit_mode !== 'READ_ONLY' && (
                                                <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-700 font-medium">{c.edit_mode}</span>
                                            )}
                                        </div>
                                        <p className="text-sm text-muted-foreground">
                                            {c.use_ssl ? 'ldaps://' : 'ldap://'}{c.host}:{c.port}
                                            {c.base_dn && <> &nbsp;·&nbsp; <code className="font-mono text-xs">{c.base_dn}</code></>}
                                            {c.sync_interval_minutes > 0 && <> &nbsp;·&nbsp; Auto-sync every {c.sync_interval_minutes} min</>}
                                        </p>
                                        {c.last_sync_at && (
                                            <p className="text-xs text-muted-foreground mt-1">Last sync: {fmtDate(c.last_sync_at)}</p>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-2 flex-shrink-0 flex-wrap justify-end">
                                        <button onClick={() => handleTest(c.id)} disabled={testing === c.id}
                                            className="text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent transition-colors disabled:opacity-50">
                                            {testing === c.id ? 'Testing…' : 'Test'}
                                        </button>
                                        <button onClick={() => handleSync(c.id)} disabled={syncing === c.id || c.sync_status === 'syncing'}
                                            className="text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent transition-colors disabled:opacity-50">
                                            {syncing === c.id ? 'Syncing…' : 'Sync Now'}
                                        </button>
                                        <button onClick={() => openDetail(c.id, 'syncHistory')}
                                            className="text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent transition-colors">
                                            History
                                        </button>
                                        <button onClick={() => openDetail(c.id, 'mappers')}
                                            className="text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent transition-colors">
                                            Mappers
                                        </button>
                                        <button onClick={() => handleToggleEnabled(c)}
                                            className="text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent transition-colors">
                                            {c.enabled ? 'Disable' : 'Enable'}
                                        </button>
                                        <button onClick={() => openEdit(c)}
                                            className="text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent transition-colors">
                                            Edit
                                        </button>
                                        <button onClick={() => handleDelete(c.id)}
                                            className="text-xs px-3 py-1.5 rounded-lg border border-destructive/30 text-destructive hover:bg-destructive/10 transition-colors">
                                            Delete
                                        </button>
                                    </div>
                                </div>
                            </div>

                            {/* Inline detail panel */}
                            {detailConn === c.id && (
                                <div className="border-t border-border bg-muted/20">
                                    <div className="flex items-center justify-between px-5 pt-3 pb-1">
                                        <div className="flex gap-1">
                                            {(['syncHistory', 'mappers'] as DetailTab[]).map(t => (
                                                <button key={t} onClick={() => { setDetailTab(t); openDetail(c.id, t); }}
                                                    className={`text-xs px-3 py-1.5 rounded-lg font-medium transition-colors ${detailTab === t ? 'bg-primary text-primary-foreground' : 'hover:bg-accent text-muted-foreground'}`}>
                                                    {t === 'syncHistory' ? 'Sync History' : 'Mappers'}
                                                </button>
                                            ))}
                                        </div>
                                        <button onClick={() => setDetailConn(null)} className="text-muted-foreground hover:text-foreground transition-colors">
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                            </svg>
                                        </button>
                                    </div>

                                    {loadingDetail ? (
                                        <div className="p-5 text-sm text-muted-foreground">Loading…</div>
                                    ) : detailTab === 'syncHistory' ? (
                                        <div className="p-4">
                                            {syncRuns.length === 0 ? (
                                                <p className="text-sm text-muted-foreground py-2">No sync runs yet.</p>
                                            ) : (
                                                <div className="space-y-2">
                                                    {syncRuns.map(r => (
                                                        <div key={r.id} className="flex items-start justify-between gap-4 bg-card border border-border rounded-xl px-4 py-3 text-sm">
                                                            <div className="min-w-0">
                                                                <div className="flex items-center gap-2 mb-0.5">
                                                                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${statusDot(r.status)}`}>{r.status}</span>
                                                                    <span className="text-xs text-muted-foreground">{fmtDate(r.started_at)}</span>
                                                                    {r.finished_at && <span className="text-xs text-muted-foreground">→ {fmtDate(r.finished_at)}</span>}
                                                                </div>
                                                                <span className="text-xs text-muted-foreground">
                                                                    Found: {r.users_found} · Created: {r.users_created} · Updated: {r.users_updated}
                                                                    {r.error_message && <> · <span className="text-destructive">{r.error_message}</span></>}
                                                                </span>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    ) : (
                                        <div className="p-4 space-y-3">
                                            {mappers.length === 0 ? (
                                                <p className="text-sm text-muted-foreground py-1">No mappers configured. Add one below.</p>
                                            ) : (
                                                <div className="space-y-2">
                                                    {mappers.map(m => (
                                                        <div key={m.id} className="flex items-center justify-between gap-3 bg-card border border-border rounded-xl px-4 py-3">
                                                            <div>
                                                                <span className="text-sm font-medium text-foreground">{m.name}</span>
                                                                <span className="ml-2 text-xs text-muted-foreground">{m.mapper_type}</span>
                                                                {m.config && (
                                                                    <span className="ml-2 text-xs font-mono text-muted-foreground">
                                                                        {JSON.stringify(m.config)}
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <button onClick={() => handleDeleteMapper(c.id, m.id)}
                                                                className="text-xs px-2 py-1 rounded-lg border border-destructive/30 text-destructive hover:bg-destructive/10 transition-colors">
                                                                Delete
                                                            </button>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                            {/* Add mapper form */}
                                            <div className="border-t border-border pt-3">
                                                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Add Mapper</p>
                                                <div className="grid grid-cols-2 gap-2 mb-2">
                                                    <input value={mapperName} onChange={e => setMapperName(e.target.value)} placeholder="Mapper name"
                                                        className={INPUT} />
                                                    <select value={mapperType} onChange={e => setMapperType(e.target.value)} className={SELECT}>
                                                        <option value="user-attribute">User Attribute</option>
                                                        <option value="role">Group → Role</option>
                                                    </select>
                                                    <input value={mapperLdapAttr} onChange={e => setMapperLdapAttr(e.target.value)}
                                                        placeholder={mapperType === 'user-attribute' ? 'LDAP attribute (e.g. mail)' : 'LDAP groups DN'}
                                                        className={MONO_INPUT} />
                                                    <input value={mapperUserAttr} onChange={e => setMapperUserAttr(e.target.value)}
                                                        placeholder={mapperType === 'user-attribute' ? 'User field (e.g. email)' : 'Role name'}
                                                        className={INPUT} />
                                                </div>
                                                <button onClick={() => handleCreateMapper(c.id)} disabled={savingMapper || !mapperName || !mapperLdapAttr}
                                                    className="text-xs px-4 py-1.5 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50">
                                                    {savingMapper ? 'Adding…' : 'Add Mapper'}
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}

            {/* Create / Edit modal */}
            {isModalOpen && (
                <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-card border border-border rounded-2xl w-full max-w-lg shadow-2xl max-h-[92vh] flex flex-col">
                        <div className="flex items-center justify-between p-6 border-b border-border flex-shrink-0">
                            <h2 className="text-lg font-bold font-heading">
                                {editingConn ? 'Edit LDAP Connection' : 'New LDAP Connection'}
                            </h2>
                            <button onClick={() => setIsModalOpen(false)} className="text-muted-foreground hover:text-foreground transition-colors">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>

                        {/* Tabs */}
                        <div className="flex gap-1 px-6 pt-3 flex-shrink-0">
                            {(['basic', 'advanced'] as ModalTab[]).map(t => (
                                <button key={t} type="button" onClick={() => setModalTab(t)}
                                    className={`text-sm px-3 py-1.5 rounded-lg font-medium transition-colors capitalize ${modalTab === t ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:text-foreground hover:bg-accent'}`}>
                                    {t === 'basic' ? 'Connection' : 'Advanced'}
                                </button>
                            ))}
                        </div>

                        <form onSubmit={handleSubmit} className="overflow-y-auto flex-1">
                            <div className="p-6 space-y-4">
                                {modalTab === 'basic' && (
                                    <>
                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-1.5">Vendor / Directory Type</label>
                                            <select value={vendor} onChange={e => applyVendorPreset(e.target.value)} className={SELECT}>
                                                {Object.entries(VENDOR_LABELS).map(([k, v]) => (
                                                    <option key={k} value={k}>{v}</option>
                                                ))}
                                            </select>
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-1.5">Connection Name</label>
                                            <input value={name} onChange={e => setName(e.target.value)} required placeholder="e.g. Corporate AD" className={INPUT} />
                                        </div>

                                        <div className="grid grid-cols-3 gap-3">
                                            <div className="col-span-2">
                                                <label className="block text-sm font-medium text-foreground mb-1.5">Hostname</label>
                                                <input value={host} onChange={e => setHost(e.target.value)} required placeholder="ldap.example.com" className={INPUT} />
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-foreground mb-1.5">Port</label>
                                                <input type="number" value={port} onChange={e => setPort(Number(e.target.value))} required className={INPUT} />
                                            </div>
                                        </div>

                                        <div className="flex items-center gap-3">
                                            <button type="button"
                                                onClick={() => { setUseSsl(!useSsl); setPort(!useSsl ? 636 : 389); }}
                                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${useSsl ? 'bg-primary' : 'bg-muted'}`}>
                                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${useSsl ? 'translate-x-6' : 'translate-x-1'}`} />
                                            </button>
                                            <label className="text-sm font-medium text-foreground">Use SSL/TLS (LDAPS)</label>
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-1.5">Bind DN</label>
                                            <input value={bindDn} onChange={e => setBindDn(e.target.value)} required
                                                placeholder="cn=admin,dc=example,dc=com" className={MONO_INPUT} />
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-1.5">
                                                Bind Password {editingConn && <span className="text-muted-foreground font-normal">(leave blank to keep existing)</span>}
                                            </label>
                                            <input type="password" value={bindPassword} onChange={e => setBindPassword(e.target.value)}
                                                required={!editingConn} placeholder="••••••••" className={INPUT} />
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-1.5">Base DN</label>
                                            <input value={baseDn} onChange={e => setBaseDn(e.target.value)} required
                                                placeholder="dc=example,dc=com" className={MONO_INPUT} />
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-1.5">User Search Filter</label>
                                            <input value={userSearchFilter} onChange={e => setUserSearchFilter(e.target.value)} required
                                                placeholder="(objectClass=person)" className={MONO_INPUT} />
                                        </div>

                                        <div className="border-t border-border pt-4">
                                            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Attribute Mapping</p>
                                            <div className="grid grid-cols-2 gap-3">
                                                <div>
                                                    <label className="block text-sm font-medium text-foreground mb-1.5">Email attribute</label>
                                                    <input value={attrEmail} onChange={e => setAttrEmail(e.target.value)} required placeholder="mail" className={MONO_INPUT} />
                                                </div>
                                                <div>
                                                    <label className="block text-sm font-medium text-foreground mb-1.5">Display name attribute</label>
                                                    <input value={attrName} onChange={e => setAttrName(e.target.value)} required placeholder="cn" className={MONO_INPUT} />
                                                </div>
                                            </div>
                                        </div>

                                        {/* Test result inline */}
                                        {editingConn && testResult && (
                                            <div className={`rounded-xl border px-4 py-3 text-sm ${testResult.success ? 'border-green-500/30 bg-green-500/5 text-green-700' : 'border-destructive/30 bg-destructive/5 text-destructive'}`}>
                                                <p className="font-medium">{testResult.success ? '✓ Test passed' : '✗ Test failed'}</p>
                                                <p className="text-xs mt-1 opacity-80">{testResult.message}</p>
                                                {testResult.naming_contexts && testResult.naming_contexts.length > 0 && (
                                                    <p className="text-xs mt-1 opacity-70 font-mono">Naming contexts: {testResult.naming_contexts.join(', ')}</p>
                                                )}
                                            </div>
                                        )}
                                    </>
                                )}

                                {modalTab === 'advanced' && (
                                    <>
                                        <div className="flex items-center gap-3">
                                            <button type="button"
                                                onClick={() => setSkipTlsVerify(!skipTlsVerify)}
                                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${skipTlsVerify ? 'bg-amber-500' : 'bg-muted'}`}>
                                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${skipTlsVerify ? 'translate-x-6' : 'translate-x-1'}`} />
                                            </button>
                                            <label className="text-sm font-medium text-foreground">
                                                Skip TLS verify <span className="text-amber-600 font-normal">(⚠ allow self-signed certs — dev/internal only)</span>
                                            </label>
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-1.5">Edit Mode</label>
                                            <select value={editMode} onChange={e => setEditMode(e.target.value)} className={SELECT}>
                                                <option value="READ_ONLY">READ_ONLY — import users, no write-back</option>
                                                <option value="WRITABLE">WRITABLE — sync changes back to LDAP</option>
                                                <option value="UNSYNCED">UNSYNCED — import once, then manage locally</option>
                                            </select>
                                        </div>

                                        <div className="flex items-center gap-3">
                                            <button type="button"
                                                onClick={() => setStartTls(!startTls)}
                                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${startTls ? 'bg-primary' : 'bg-muted'}`}>
                                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${startTls ? 'translate-x-6' : 'translate-x-1'}`} />
                                            </button>
                                            <label className="text-sm font-medium text-foreground">
                                                STARTTLS <span className="text-muted-foreground font-normal">(TLS upgrade on plain LDAP port, ignored when SSL/LDAPS is enabled)</span>
                                            </label>
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-1.5">
                                                Auto-sync interval (minutes) <span className="text-muted-foreground font-normal">— 0 = disabled</span>
                                            </label>
                                            <input type="number" min="0" value={syncInterval} onChange={e => setSyncInterval(Number(e.target.value))} className={INPUT} />
                                        </div>

                                        <div className="grid grid-cols-2 gap-3">
                                            <div>
                                                <label className="block text-sm font-medium text-foreground mb-1.5">Connection timeout (secs)</label>
                                                <input type="number" min="3" value={connTimeout} onChange={e => setConnTimeout(Number(e.target.value))} className={INPUT} />
                                            </div>
                                            <div>
                                                <label className="block text-sm font-medium text-foreground mb-1.5">Read timeout (secs)</label>
                                                <input type="number" min="5" value={readTimeout} onChange={e => setReadTimeout(Number(e.target.value))} className={INPUT} />
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-2 gap-3">
                                            <div>
                                                <label className="block text-sm font-medium text-foreground mb-1.5">Page size</label>
                                                <input type="number" min="10" value={pageSize} onChange={e => setPageSize(Number(e.target.value))} className={INPUT} />
                                            </div>
                                        </div>

                                        <div className="border-t border-border pt-4">
                                            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Identity Attributes</p>
                                            <div className="grid grid-cols-2 gap-3">
                                                <div>
                                                    <label className="block text-sm font-medium text-foreground mb-1.5">
                                                        UUID attribute <span className="text-muted-foreground font-normal">(stable ID)</span>
                                                    </label>
                                                    <input value={uuidAttr} onChange={e => setUuidAttr(e.target.value)} placeholder="entryUUID" className={MONO_INPUT} />
                                                    <p className="text-xs text-muted-foreground mt-1">Use <code>objectGUID</code> for AD</p>
                                                </div>
                                                <div>
                                                    <label className="block text-sm font-medium text-foreground mb-1.5">Username attribute</label>
                                                    <input value={usernameAttr} onChange={e => setUsernameAttr(e.target.value)} placeholder="uid" className={MONO_INPUT} />
                                                    <p className="text-xs text-muted-foreground mt-1">Use <code>sAMAccountName</code> for AD</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="border-t border-border pt-4">
                                            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Group Federation</p>
                                            <div className="space-y-3">
                                                <div>
                                                    <label className="block text-sm font-medium text-foreground mb-1.5">
                                                        Groups base DN <span className="text-muted-foreground font-normal">(leave blank to skip group sync)</span>
                                                    </label>
                                                    <input value={groupsDn} onChange={e => setGroupsDn(e.target.value)}
                                                        placeholder="ou=groups,dc=example,dc=com" className={MONO_INPUT} />
                                                </div>
                                                <div className="grid grid-cols-2 gap-3">
                                                    <div>
                                                        <label className="block text-sm font-medium text-foreground mb-1.5">Group name attribute</label>
                                                        <input value={groupNameAttr} onChange={e => setGroupNameAttr(e.target.value)} placeholder="cn" className={MONO_INPUT} />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-foreground mb-1.5">Group object class</label>
                                                        <input value={groupObjectClass} onChange={e => setGroupObjectClass(e.target.value)} placeholder="groupOfNames" className={MONO_INPUT} />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-foreground mb-1.5">Membership attribute</label>
                                                        <input value={groupMemberAttr} onChange={e => setGroupMemberAttr(e.target.value)} placeholder="member" className={MONO_INPUT} />
                                                    </div>
                                                    <div>
                                                        <label className="block text-sm font-medium text-foreground mb-1.5">Membership type</label>
                                                        <select value={groupMemberType} onChange={e => setGroupMemberType(e.target.value)} className={SELECT}>
                                                            <option value="DN">DN (member: cn=user,dc=...)</option>
                                                            <option value="UID">UID (memberUid: username)</option>
                                                        </select>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="border-t border-border pt-4">
                                            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Failover &amp; Search</p>
                                            <div className="space-y-3">
                                                <div>
                                                    <label className="block text-sm font-medium text-foreground mb-1.5">
                                                        Failover hosts <span className="text-muted-foreground font-normal">(comma-separated)</span>
                                                    </label>
                                                    <input value={failoverHosts} onChange={e => setFailoverHosts(e.target.value)}
                                                        placeholder="dc2.company.com,dc3.company.com" className={MONO_INPUT} />
                                                    <p className="text-xs text-muted-foreground mt-1">Tried in order if primary host is unreachable.</p>
                                                </div>
                                                <div>
                                                    <label className="block text-sm font-medium text-foreground mb-1.5">Search scope</label>
                                                    <select value={searchScope} onChange={e => setSearchScope(e.target.value)} className={SELECT}>
                                                        <option value="subtree">Subtree (recursive, default)</option>
                                                        <option value="onelevel">One level (direct children only)</option>
                                                        <option value="base">Base (base DN only)</option>
                                                    </select>
                                                </div>
                                            </div>
                                        </div>
                                    </>
                                )}
                            </div>

                            <div className="flex gap-3 px-6 pb-6 flex-shrink-0">
                                {editingConn && modalTab === 'basic' && (
                                    <button type="button" onClick={() => handleTest(editingConn.id)} disabled={testing === editingConn.id}
                                        className="px-4 py-2 rounded-xl border border-border text-sm font-semibold hover:bg-accent transition-colors disabled:opacity-50">
                                        {testing === editingConn.id ? 'Testing…' : 'Test'}
                                    </button>
                                )}
                                <button type="button" onClick={() => setIsModalOpen(false)}
                                    className="flex-1 px-4 py-2 rounded-xl border border-border text-sm font-semibold hover:bg-accent transition-colors">
                                    Cancel
                                </button>
                                <button type="submit" disabled={saving}
                                    className="flex-1 px-4 py-2 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-semibold transition-colors disabled:opacity-50">
                                    {saving ? 'Saving…' : editingConn ? 'Save Changes' : 'Create Connection'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}

