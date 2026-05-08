import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { api } from '../../lib/api';
import { Badge, Button, Input, PageHeader } from '../../components/ui';
import { useAuth } from '../auth/AuthContext';
import type { User } from '../auth/types';

interface AdminUser {
  id: string;
  createdAt: string;
  firstName?: string;
  lastName?: string;
  profileImageUrl?: string;
  banned: boolean;
  locked: boolean;
  email?: string;
  emailVerified?: boolean;
  phone?: string;
  phoneVerified?: boolean;
  role?: string;
  attributes?: Record<string, unknown>;
}

interface CreateUserForm {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phone: string;
  role: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  forcePasswordReset: boolean;
  requireEmailVerification: boolean;
  requirePhoneVerification: boolean;
  attributesJson: string;
}

interface EditUserForm {
  email: string;
  phone: string;
  firstName: string;
  lastName: string;
  role: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  locked: boolean;
  banned: boolean;
  attributesJson: string;
}

interface ImpersonateResponse {
  jwt: string;
  tenantId: string;
  user: User;
}

const emptyForm: CreateUserForm = {
  email: '',
  password: '',
  firstName: '',
  lastName: '',
  phone: '',
  role: 'member',
  emailVerified: false,
  phoneVerified: false,
  forcePasswordReset: true,
  requireEmailVerification: false,
  requirePhoneVerification: false,
  attributesJson: '{}',
};

const roles = ['member', 'admin', 'billing_manager', 'guest'];

export default function UsersPage() {
  const { setAuth } = useAuth();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<CreateUserForm>(emptyForm);
  const [selected, setSelected] = useState<AdminUser | null>(null);
  const [editForm, setEditForm] = useState<EditUserForm | null>(null);

  const selectedDisplayName = useMemo(() => {
    if (!selected) return '';
    return [selected.firstName, selected.lastName].filter(Boolean).join(' ') || selected.email || selected.id;
  }, [selected]);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const res = await api.get<AdminUser[]>('/api/admin/v1/users', {
        params: query.trim() ? { q: query.trim() } : undefined,
      });
      setUsers(res.data);
      if (selected) {
        const updated = res.data.find((user) => user.id === selected.id) || null;
        setSelected(updated);
        if (updated && editForm) setEditForm(toEditForm(updated));
      }
    } catch (error) {
      console.error('Failed to load users', error);
      toast.error('Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const createUser = async () => {
    let attributes: Record<string, unknown>;
    try {
      attributes = parseAttributes(form.attributesJson);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Invalid attributes JSON');
      return;
    }

    setCreating(true);
    try {
      const requiredActions = [
        form.forcePasswordReset ? 'update_password' : null,
        form.requireEmailVerification ? 'verify_email' : null,
        form.requirePhoneVerification ? 'verify_phone' : null,
      ].filter(Boolean);

      await api.post('/api/admin/v1/users', {
        email: form.email,
        password: form.password || undefined,
        firstName: form.firstName || undefined,
        lastName: form.lastName || undefined,
        phone: form.phone || undefined,
        role: form.role,
        emailVerified: form.emailVerified,
        phoneVerified: form.phoneVerified,
        requiredActions,
        attributes,
      });
      toast.success('User created');
      setForm(emptyForm);
      setShowCreate(false);
      loadUsers();
    } catch (error) {
      console.error('Failed to create user', error);
      toast.error('Failed to create user');
    } finally {
      setCreating(false);
    }
  };

  const openEdit = (user: AdminUser) => {
    setSelected(user);
    setEditForm(toEditForm(user));
  };

  const saveUser = async () => {
    if (!selected || !editForm) return;

    let attributes: Record<string, unknown>;
    try {
      attributes = parseAttributes(editForm.attributesJson);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Invalid attributes JSON');
      return;
    }

    setSaving(true);
    try {
      const res = await api.patch<AdminUser>(`/api/admin/v1/users/${selected.id}`, {
        email: editForm.email || undefined,
        phone: editForm.phone.trim() ? editForm.phone.trim() : null,
        firstName: editForm.firstName || undefined,
        lastName: editForm.lastName || undefined,
        role: editForm.role,
        emailVerified: editForm.emailVerified,
        phoneVerified: editForm.phoneVerified,
        locked: editForm.locked,
        banned: editForm.banned,
        attributes,
      });
      toast.success('User updated');
      setSelected(res.data);
      setEditForm(toEditForm(res.data));
      loadUsers();
    } catch (error) {
      console.error('Failed to update user', error);
      toast.error('Failed to update user');
    } finally {
      setSaving(false);
    }
  };

  const setLocked = async (user: AdminUser, locked: boolean) => {
    try {
      await api.post(`/api/admin/v1/users/${user.id}/${locked ? 'lock' : 'unlock'}`);
      toast.success(locked ? 'User locked' : 'User unlocked');
      loadUsers();
    } catch (error) {
      console.error('Failed to update lock state', error);
      toast.error('Failed to update lock state');
    }
  };

  const assignAction = async (user: AdminUser, code: string) => {
    try {
      await api.post(`/api/admin/v1/users/${user.id}/required-actions`, { codes: [code] });
      toast.success('Required action assigned');
    } catch (error) {
      console.error('Failed to assign required action', error);
      toast.error('Failed to assign required action');
    }
  };

  const forcePasswordChange = async (user: AdminUser) => {
    try {
      await api.post(`/api/admin/v1/users/${user.id}/force-password-change`);
      toast.success('Password change required at next sign-in');
    } catch (error) {
      console.error('Failed to force password change', error);
      toast.error('Failed to force password change');
    }
  };

  const impersonate = async (user: AdminUser) => {
    if (!confirm(`Impersonate ${user.email || user.id}?`)) return;
    try {
      const res = await api.post<ImpersonateResponse>(`/api/admin/v1/users/${user.id}/impersonate`, {
        reason: 'admin_console',
      });
      setAuth(res.data.jwt, { ...res.data.user, organization_id: res.data.tenantId });
      toast.success('Impersonation session started');
      window.location.href = '/account/profile';
    } catch (error) {
      console.error('Failed to impersonate user', error);
      toast.error('Failed to impersonate user');
    }
  };

  const deleteUser = async (user: AdminUser) => {
    if (!confirm(`Delete ${user.email || user.id}?`)) return;
    try {
      await api.delete(`/api/admin/v1/users/${user.id}`);
      toast.success('User deleted');
      if (selected?.id === user.id) {
        setSelected(null);
        setEditForm(null);
      }
      loadUsers();
    } catch (error) {
      console.error('Failed to delete user', error);
      toast.error('Failed to delete user');
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader title="Users" description="Manage tenant users, attributes, verification, required actions, and impersonation.">
        <Button size="sm" onClick={() => setShowCreate((value) => !value)}>
          {showCreate ? 'Close' : 'Create User'}
        </Button>
      </PageHeader>

      {showCreate && (
        <div className="rounded-xl border border-border bg-card p-4">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <Input label="Email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} />
            <Input label="Phone" value={form.phone} onChange={(event) => setForm({ ...form, phone: event.target.value })} />
            <Input label="Temporary Password" type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} />
            <Input label="First Name" value={form.firstName} onChange={(event) => setForm({ ...form, firstName: event.target.value })} />
            <Input label="Last Name" value={form.lastName} onChange={(event) => setForm({ ...form, lastName: event.target.value })} />
            <label className="space-y-1.5 text-sm font-medium text-foreground">
              Role
              <select className="block h-10 w-full rounded-xl border border-input bg-background px-3 text-sm" value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>
                {roles.map((role) => <option key={role} value={role}>{formatRole(role)}</option>)}
              </select>
            </label>
          </div>
          <label className="mt-4 block space-y-1.5 text-sm font-medium text-foreground">
            Custom Attributes
            <textarea className="min-h-24 w-full rounded-xl border border-input bg-background px-3 py-2 font-mono text-sm" value={form.attributesJson} onChange={(event) => setForm({ ...form, attributesJson: event.target.value })} />
          </label>
          <div className="mt-4 flex flex-wrap items-center gap-4">
            <Checkbox checked={form.emailVerified} label="Email verified" onChange={(checked) => setForm({ ...form, emailVerified: checked })} />
            <Checkbox checked={form.phoneVerified} label="Phone verified" onChange={(checked) => setForm({ ...form, phoneVerified: checked })} />
            <Checkbox checked={form.forcePasswordReset} label="Force password reset" onChange={(checked) => setForm({ ...form, forcePasswordReset: checked })} />
            <Checkbox checked={form.requireEmailVerification} label="Require email verification" onChange={(checked) => setForm({ ...form, requireEmailVerification: checked })} />
            <Checkbox checked={form.requirePhoneVerification} label="Require phone verification" onChange={(checked) => setForm({ ...form, requirePhoneVerification: checked })} />
            <Button loading={creating} onClick={createUser}>Create</Button>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <Input label="Search" placeholder="Email, phone, name, or user ID" value={query} onChange={(event) => setQuery(event.target.value)} />
        <Button variant="outline" onClick={loadUsers}>Search</Button>
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="overflow-hidden rounded-xl border border-border bg-card">
          <table className="min-w-full divide-y divide-border">
            <thead className="bg-muted/30">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">User</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">Role</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-right text-xs font-semibold uppercase text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading && <tr><td colSpan={4} className="px-4 py-10 text-center text-muted-foreground">Loading users...</td></tr>}
              {!loading && users.length === 0 && <tr><td colSpan={4} className="px-4 py-10 text-center text-muted-foreground">No users found.</td></tr>}
              {users.map((user) => (
                <tr key={user.id} className={selected?.id === user.id ? 'bg-primary/5' : undefined}>
                  <td className="px-4 py-3">
                    <div className="font-medium text-foreground">{[user.firstName, user.lastName].filter(Boolean).join(' ') || user.email || user.id}</div>
                    <div className="text-xs text-muted-foreground">{user.email || user.id}</div>
                    {user.phone && <div className="text-xs text-muted-foreground">{user.phone}</div>}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">{formatRole(user.role || 'member')}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-2">
                      <Badge variant={user.emailVerified ? 'success' : 'warning'}>{user.emailVerified ? 'Email' : 'Email pending'}</Badge>
                      {user.phone && <Badge variant={user.phoneVerified ? 'success' : 'warning'}>{user.phoneVerified ? 'Phone' : 'Phone pending'}</Badge>}
                      <Badge variant={user.locked ? 'danger' : 'muted'}>{user.locked ? 'Locked' : 'Active'}</Badge>
                      {user.banned && <Badge variant="danger">Banned</Badge>}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap justify-end gap-2">
                      <Button size="sm" variant="outline" onClick={() => openEdit(user)}>Edit</Button>
                      <Button size="sm" variant="outline" onClick={() => impersonate(user)}>Impersonate</Button>
                      <Button size="sm" variant="outline" onClick={() => setLocked(user, !user.locked)}>{user.locked ? 'Unlock' : 'Lock'}</Button>
                      <Button size="sm" variant="outline" onClick={() => assignAction(user, 'verify_email')}>Email Check</Button>
                      {user.phone && <Button size="sm" variant="outline" onClick={() => assignAction(user, 'verify_phone')}>Phone Check</Button>}
                      <Button size="sm" variant="outline" onClick={() => forcePasswordChange(user)}>Password Reset</Button>
                      <Button size="sm" variant="destructive" onClick={() => deleteUser(user)}>Delete</Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="rounded-xl border border-border bg-card p-4">
          {!selected || !editForm ? (
            <div className="py-12 text-center text-sm text-muted-foreground">Select a user to edit profile, status, role, and custom attributes.</div>
          ) : (
            <div className="space-y-4">
              <div>
                <h3 className="font-semibold text-foreground">{selectedDisplayName}</h3>
                <p className="text-xs text-muted-foreground">{selected.id}</p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
                <Input label="Email" value={editForm.email} onChange={(event) => setEditForm({ ...editForm, email: event.target.value })} />
                <Input label="Phone" value={editForm.phone} onChange={(event) => setEditForm({ ...editForm, phone: event.target.value })} />
                <Input label="First Name" value={editForm.firstName} onChange={(event) => setEditForm({ ...editForm, firstName: event.target.value })} />
                <Input label="Last Name" value={editForm.lastName} onChange={(event) => setEditForm({ ...editForm, lastName: event.target.value })} />
                <label className="space-y-1.5 text-sm font-medium text-foreground">
                  Role
                  <select className="block h-10 w-full rounded-xl border border-input bg-background px-3 text-sm" value={editForm.role} onChange={(event) => setEditForm({ ...editForm, role: event.target.value })}>
                    {roles.map((role) => <option key={role} value={role}>{formatRole(role)}</option>)}
                  </select>
                </label>
              </div>
              <label className="block space-y-1.5 text-sm font-medium text-foreground">
                Custom Attributes
                <textarea className="min-h-32 w-full rounded-xl border border-input bg-background px-3 py-2 font-mono text-sm" value={editForm.attributesJson} onChange={(event) => setEditForm({ ...editForm, attributesJson: event.target.value })} />
              </label>
              <div className="flex flex-wrap gap-3">
                <Checkbox checked={editForm.emailVerified} label="Email verified" onChange={(checked) => setEditForm({ ...editForm, emailVerified: checked })} />
                <Checkbox checked={editForm.phoneVerified} label="Phone verified" onChange={(checked) => setEditForm({ ...editForm, phoneVerified: checked })} />
                <Checkbox checked={editForm.locked} label="Locked" onChange={(checked) => setEditForm({ ...editForm, locked: checked })} />
                <Checkbox checked={editForm.banned} label="Banned" onChange={(checked) => setEditForm({ ...editForm, banned: checked })} />
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => { setSelected(null); setEditForm(null); }}>Close</Button>
                <Button loading={saving} onClick={saveUser}>Save</Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function toEditForm(user: AdminUser): EditUserForm {
  return {
    email: user.email || '',
    phone: user.phone || '',
    firstName: user.firstName || '',
    lastName: user.lastName || '',
    role: user.role || 'member',
    emailVerified: Boolean(user.emailVerified),
    phoneVerified: Boolean(user.phoneVerified),
    locked: user.locked,
    banned: user.banned,
    attributesJson: JSON.stringify(user.attributes || {}, null, 2),
  };
}

function parseAttributes(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value || '{}') as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Attributes must be a JSON object');
  }
  return parsed as Record<string, unknown>;
}

function formatRole(role: string): string {
  return role.replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

function Checkbox({ checked, label, onChange }: { checked: boolean; label: string; onChange: (checked: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm text-foreground">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}
