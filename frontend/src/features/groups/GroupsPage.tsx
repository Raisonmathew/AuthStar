import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { api } from '../../lib/api';
import { Badge, Button, Input, PageHeader } from '../../components/ui';

interface Group {
  id: string;
  name: string;
  slug: string;
  description?: string;
  parentGroupId?: string;
  memberCount: number;
  roleCount: number;
}

interface GroupMember {
  userId: string;
  email?: string;
  firstName?: string;
  lastName?: string;
}

interface GroupRole {
  roleId: string;
  name: string;
  description?: string;
}

interface RoleOption {
  id: string;
  name: string;
}

interface GroupDetails {
  group: Group;
  members: GroupMember[];
  roles: GroupRole[];
}

export default function GroupsPage() {
  const [groups, setGroups] = useState<Group[]>([]);
  const [roles, setRoles] = useState<RoleOption[]>([]);
  const [selected, setSelected] = useState<GroupDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [description, setDescription] = useState('');
  const [parentGroupId, setParentGroupId] = useState('');
  const [memberId, setMemberId] = useState('');
  const [roleId, setRoleId] = useState('');
  const [editName, setEditName] = useState('');
  const [editSlug, setEditSlug] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [editParentGroupId, setEditParentGroupId] = useState('');

  const groupDepth = useMemo(() => computeGroupDepth(groups), [groups]);
  const sortedGroups = useMemo(() => sortGroupsAsTree(groups), [groups]);

  const loadGroups = async () => {
    setLoading(true);
    try {
      const res = await api.get<Group[]>('/api/admin/v1/groups');
      setGroups(res.data);
      if (selected) {
        await loadGroup(selected.group.id);
      }
    } catch (error) {
      console.error('Failed to load groups', error);
      toast.error('Failed to load groups');
    } finally {
      setLoading(false);
    }
  };

  const loadRoles = async () => {
    try {
      const orgId = sessionStorage.getItem('active_org_id');
      if (!orgId) return;
      const res = await api.get<RoleOption[]>(`/api/v1/organizations/${orgId}/roles`);
      setRoles(res.data);
    } catch (error) {
      console.error('Failed to load roles', error);
    }
  };

  const loadGroup = async (id: string) => {
    const res = await api.get<GroupDetails>(`/api/admin/v1/groups/${id}`);
    setSelected(res.data);
    setEditName(res.data.group.name);
    setEditSlug(res.data.group.slug);
    setEditDescription(res.data.group.description || '');
    setEditParentGroupId(res.data.group.parentGroupId || '');
  };

  useEffect(() => {
    loadGroups();
    loadRoles();
  }, []);

  const createGroup = async () => {
    try {
      await api.post('/api/admin/v1/groups', {
        name,
        slug: slug || undefined,
        parentGroupId: parentGroupId || undefined,
        description: description || undefined,
      });
      toast.success('Group created');
      setName('');
      setSlug('');
      setDescription('');
      setParentGroupId('');
      loadGroups();
    } catch (error) {
      console.error('Failed to create group', error);
      toast.error('Failed to create group');
    }
  };

  const updateGroup = async () => {
    if (!selected) return;
    try {
      const res = await api.patch<Group>(`/api/admin/v1/groups/${selected.group.id}`, {
        name: editName,
        slug: editSlug,
        parentGroupId: editParentGroupId || null,
        description: editDescription || null,
      });
      toast.success('Group updated');
      setSelected({ ...selected, group: res.data });
      loadGroups();
    } catch (error) {
      console.error('Failed to update group', error);
      toast.error('Failed to update group');
    }
  };

  const deleteGroup = async (group: Group) => {
    if (!confirm(`Delete group ${group.name}?`)) return;
    try {
      await api.delete(`/api/admin/v1/groups/${group.id}`);
      toast.success('Group deleted');
      setSelected(null);
      loadGroups();
    } catch (error) {
      console.error('Failed to delete group', error);
      toast.error('Failed to delete group');
    }
  };

  const addMember = async () => {
    if (!selected || !memberId.trim()) return;
    try {
      const res = await api.post<GroupMember[]>(`/api/admin/v1/groups/${selected.group.id}/members`, { userId: memberId.trim() });
      setSelected({ ...selected, members: res.data });
      setMemberId('');
      loadGroups();
    } catch (error) {
      console.error('Failed to add member', error);
      toast.error('Failed to add member');
    }
  };

  const removeMember = async (userId: string) => {
    if (!selected) return;
    const res = await api.delete<GroupMember[]>(`/api/admin/v1/groups/${selected.group.id}/members/${userId}`);
    setSelected({ ...selected, members: res.data });
    loadGroups();
  };

  const addRole = async () => {
    if (!selected || !roleId.trim()) return;
    try {
      const res = await api.post<GroupRole[]>(`/api/admin/v1/groups/${selected.group.id}/roles`, { roleId: roleId.trim() });
      setSelected({ ...selected, roles: res.data });
      setRoleId('');
      loadGroups();
    } catch (error) {
      console.error('Failed to bind role', error);
      toast.error('Failed to bind role');
    }
  };

  const removeRole = async (currentRoleId: string) => {
    if (!selected) return;
    const res = await api.delete<GroupRole[]>(`/api/admin/v1/groups/${selected.group.id}/roles/${currentRoleId}`);
    setSelected({ ...selected, roles: res.data });
    loadGroups();
  };

  return (
    <div className="space-y-6">
      <PageHeader title="Groups" description="Build hierarchical identity containers and bind them to existing roles." />

      <div className="rounded-xl border border-border bg-card p-4">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Input label="Name" value={name} onChange={(event) => setName(event.target.value)} />
          <Input label="Slug" value={slug} onChange={(event) => setSlug(event.target.value)} placeholder="Generated if empty" />
          <Input label="Description" value={description} onChange={(event) => setDescription(event.target.value)} />
          <label className="space-y-1.5 text-sm font-medium text-foreground">
            Parent
            <select className="block h-10 w-full rounded-xl border border-input bg-background px-3 text-sm" value={parentGroupId} onChange={(event) => setParentGroupId(event.target.value)}>
              <option value="">Root group</option>
              {sortedGroups.map((group) => <option key={group.id} value={group.id}>{treeLabel(group, groupDepth)}</option>)}
            </select>
          </label>
        </div>
        <div className="mt-4">
          <Button onClick={createGroup}>Create Group</Button>
        </div>
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_440px]">
        <div className="overflow-hidden rounded-xl border border-border bg-card">
          <table className="min-w-full divide-y divide-border">
            <thead className="bg-muted/30">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">Group</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">Members</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">Roles</th>
                <th className="px-4 py-3 text-right text-xs font-semibold uppercase text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading && <tr><td colSpan={4} className="px-4 py-10 text-center text-muted-foreground">Loading groups...</td></tr>}
              {!loading && groups.length === 0 && <tr><td colSpan={4} className="px-4 py-10 text-center text-muted-foreground">No groups found.</td></tr>}
              {sortedGroups.map((group) => (
                <tr key={group.id} className={selected?.group.id === group.id ? 'bg-primary/5' : undefined}>
                  <td className="px-4 py-3">
                    <div className="font-medium text-foreground" style={{ paddingLeft: `${(groupDepth.get(group.id) || 0) * 18}px` }}>{group.name}</div>
                    <div className="text-xs text-muted-foreground" style={{ paddingLeft: `${(groupDepth.get(group.id) || 0) * 18}px` }}>{group.slug}</div>
                  </td>
                  <td className="px-4 py-3"><Badge variant="muted">{group.memberCount}</Badge></td>
                  <td className="px-4 py-3"><Badge variant="muted">{group.roleCount}</Badge></td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-2">
                      <Button size="sm" variant="outline" onClick={() => loadGroup(group.id)}>Open</Button>
                      <Button size="sm" variant="destructive" onClick={() => deleteGroup(group)}>Delete</Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="rounded-xl border border-border bg-card p-4">
          {!selected ? (
            <div className="py-12 text-center text-sm text-muted-foreground">Select a group to edit hierarchy, members, and role bindings.</div>
          ) : (
            <div className="space-y-6">
              <div>
                <h3 className="font-semibold text-foreground">{selected.group.name}</h3>
                <p className="text-xs text-muted-foreground">{selected.group.id}</p>
              </div>

              <section className="space-y-3">
                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
                  <Input label="Name" value={editName} onChange={(event) => setEditName(event.target.value)} />
                  <Input label="Slug" value={editSlug} onChange={(event) => setEditSlug(event.target.value)} />
                  <Input label="Description" value={editDescription} onChange={(event) => setEditDescription(event.target.value)} />
                  <label className="space-y-1.5 text-sm font-medium text-foreground">
                    Parent
                    <select className="block h-10 w-full rounded-xl border border-input bg-background px-3 text-sm" value={editParentGroupId} onChange={(event) => setEditParentGroupId(event.target.value)}>
                      <option value="">Root group</option>
                      {sortedGroups.filter((group) => group.id !== selected.group.id).map((group) => <option key={group.id} value={group.id}>{treeLabel(group, groupDepth)}</option>)}
                    </select>
                  </label>
                </div>
                <div className="flex justify-end">
                  <Button variant="outline" onClick={updateGroup}>Save Group</Button>
                </div>
              </section>

              <section className="space-y-3">
                <div className="flex items-end gap-2">
                  <Input label="User ID" value={memberId} onChange={(event) => setMemberId(event.target.value)} />
                  <Button variant="outline" onClick={addMember}>Add</Button>
                </div>
                <div className="space-y-2">
                  {selected.members.map((member) => (
                    <div key={member.userId} className="flex items-center justify-between rounded-lg border border-border px-3 py-2 text-sm">
                      <span>{member.email || member.userId}</span>
                      <button className="text-destructive" onClick={() => removeMember(member.userId)}>Remove</button>
                    </div>
                  ))}
                  {selected.members.length === 0 && <div className="text-sm text-muted-foreground">No members in this group.</div>}
                </div>
              </section>

              <section className="space-y-3">
                <div className="flex items-end gap-2">
                  <label className="flex-1 space-y-1.5 text-sm font-medium text-foreground">
                    Role
                    <select className="block h-10 w-full rounded-xl border border-input bg-background px-3 text-sm" value={roleId} onChange={(event) => setRoleId(event.target.value)}>
                      <option value="">Select role</option>
                      {roles.map((role) => <option key={role.id} value={role.id}>{role.name}</option>)}
                    </select>
                  </label>
                  <Button variant="outline" onClick={addRole}>Bind</Button>
                </div>
                <div className="space-y-2">
                  {selected.roles.map((role) => (
                    <div key={role.roleId} className="flex items-center justify-between rounded-lg border border-border px-3 py-2 text-sm">
                      <span>{role.name}</span>
                      <button className="text-destructive" onClick={() => removeRole(role.roleId)}>Remove</button>
                    </div>
                  ))}
                  {selected.roles.length === 0 && <div className="text-sm text-muted-foreground">No roles bound to this group.</div>}
                </div>
              </section>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function computeGroupDepth(groups: Group[]): Map<string, number> {
  const byId = new Map(groups.map((group) => [group.id, group]));
  const memo = new Map<string, number>();

  const depthOf = (group: Group, seen = new Set<string>()): number => {
    if (memo.has(group.id)) return memo.get(group.id) || 0;
    if (!group.parentGroupId || seen.has(group.id)) {
      memo.set(group.id, 0);
      return 0;
    }
    seen.add(group.id);
    const parent = byId.get(group.parentGroupId);
    const depth = parent ? depthOf(parent, seen) + 1 : 0;
    memo.set(group.id, depth);
    return depth;
  };

  groups.forEach((group) => depthOf(group));
  return memo;
}

function sortGroupsAsTree(groups: Group[]): Group[] {
  const children = new Map<string, Group[]>();
  const roots: Group[] = [];

  groups.forEach((group) => {
    if (group.parentGroupId) {
      children.set(group.parentGroupId, [...(children.get(group.parentGroupId) || []), group]);
    } else {
      roots.push(group);
    }
  });

  const sortByName = (items: Group[]) => items.sort((a, b) => a.name.localeCompare(b.name));
  const output: Group[] = [];
  const visit = (group: Group) => {
    output.push(group);
    sortByName(children.get(group.id) || []).forEach(visit);
  };

  sortByName(roots).forEach(visit);
  return output;
}

function treeLabel(group: Group, depthById: Map<string, number>): string {
  return `${'  '.repeat(depthById.get(group.id) || 0)}${group.name}`;
}
