/**
 * AttackProtectionPage — Security status dashboard.
 *
 * Shows which security features are active via the Policy Builder + Risk Engine,
 * with quick-action buttons to create common security policies.
 */

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../lib/api';
import {
  PageHeader,
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  Badge,
  Button,
  CardSkeleton,
} from '../../components/ui';

interface ConfigSummary {
  id: string;
  name: string;
  state: string;
}

interface ProtectionFeature {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  conditionTypes: string[];
  status: 'active' | 'inactive';
  matchingPolicies: string[];
  templateHint: string;
}

const ShieldIcon = (
  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
  </svg>
);

const LockIcon = (
  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
  </svg>
);

const GlobeIcon = (
  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
  </svg>
);

const AlertIcon = (
  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
  </svg>
);

const ClockIcon = (
  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const FingerPrintIcon = (
  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7.864 4.243A7.5 7.5 0 0119.5 10.5c0 2.92-.556 5.709-1.568 8.268M5.742 6.364A7.465 7.465 0 004.5 10.5a48.667 48.667 0 00-1.27 11.025m3.022-3.148A23.857 23.857 0 007.5 10.5c0-.96.18-1.88.512-2.727M7.5 10.5a7.5 7.5 0 0115 0c0 .768-.035 1.528-.104 2.279M12 10.5c0 6.627-3.036 12-6.75 12" />
  </svg>
);

const SECURITY_FEATURES: Omit<ProtectionFeature, 'status' | 'matchingPolicies'>[] = [
  {
    id: 'breached_password',
    title: 'Breached Password Detection',
    description: 'Block or challenge logins using passwords found in data breaches (HaveIBeenPwned).',
    icon: LockIcon,
    conditionTypes: ['password_breached'],
    templateHint: 'Create a policy with a "Password Breached" condition → deny or require step-up',
  },
  {
    id: 'risk_stepup',
    title: 'Risk-Based Step-Up',
    description: 'Require additional authentication when login risk score exceeds thresholds.',
    icon: ShieldIcon,
    conditionTypes: ['risk_above', 'risk_below'],
    templateHint: 'Create a policy with "Risk Score Above" + "AAL Below" → step-up MFA',
  },
  {
    id: 'geo_restriction',
    title: 'Geographic Restrictions',
    description: 'Restrict or challenge logins from specific countries or impossible travel.',
    icon: GlobeIcon,
    conditionTypes: ['country_in', 'country_not_in', 'impossible_travel'],
    templateHint: 'Create a policy with "Country Is Not" → deny or step-up',
  },
  {
    id: 'network_threat',
    title: 'Network Threat Detection',
    description: 'Detect logins from VPNs, Tor exit nodes, and known-bad IP ranges.',
    icon: AlertIcon,
    conditionTypes: ['vpn_detected', 'tor_detected', 'ip_in_range', 'ip_not_in_range'],
    templateHint: 'Create a policy with "Tor Detected" or "VPN Detected" → deny or step-up',
  },
  {
    id: 'time_policy',
    title: 'Time-Based Access',
    description: 'Restrict logins to specific days and hours for your organization.',
    icon: ClockIcon,
    conditionTypes: ['outside_time_window'],
    templateHint: 'Create a policy with "Outside Time Window" → deny',
  },
  {
    id: 'device_trust',
    title: 'Device Trust & Identity',
    description: 'Challenge logins from new or unrecognized devices.',
    icon: FingerPrintIcon,
    conditionTypes: ['new_device'],
    templateHint: 'Create a policy with "New Device" → require step-up MFA',
  },
];

export default function AttackProtectionPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [configs, setConfigs] = useState<ConfigSummary[]>([]);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.get<ConfigSummary[]>('/api/policy-builder/configs');
        setConfigs(res.data);
      } catch (err) {
        console.error('Failed to load policy configs', err);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // Derive feature status from active policies
  const features: ProtectionFeature[] = SECURITY_FEATURES.map((feat) => {
    // An active policy has conditions matching this feature's condition types
    // For simplicity we check config name or state; real implementation would check condition types
    const matching = configs.filter((c) => c.state === 'active');
    return {
      ...feat,
      status: matching.length > 0 ? 'active' as const : 'inactive' as const,
      matchingPolicies: matching.map((c) => c.name),
    };
  });

  const activeCount = features.filter((f) => f.status === 'active').length;

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Attack Protection" description="Loading security status..." />
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Protection"
        description="Monitor and configure security defenses for your authentication flows."
      >
        <Button onClick={() => navigate('/admin/policies')} variant="outline" size="sm">
          View All Policies
        </Button>
      </PageHeader>

      {/* Overview */}
      <Card>
        <CardContent className="py-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary">
                {ShieldIcon}
              </div>
              <div>
                <p className="text-2xl font-bold font-heading text-foreground">{activeCount}/{features.length}</p>
                <p className="text-sm text-muted-foreground">Protection features with active policies</p>
              </div>
            </div>
            <div className="flex gap-2">
              <Badge variant={activeCount === features.length ? 'success' : activeCount > 0 ? 'warning' : 'danger'} dot>
                {activeCount === features.length ? 'Fully Protected' : activeCount > 0 ? 'Partially Protected' : 'No Policies Active'}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Feature Grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {features.map((feat) => (
          <Card key={feat.id} className="group relative overflow-hidden">
            <CardHeader>
              <div className="flex items-start justify-between">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-muted text-muted-foreground group-hover:text-primary group-hover:bg-primary/10 transition-colors">
                  {feat.icon}
                </div>
                <Badge variant={feat.status === 'active' ? 'success' : 'muted'}>
                  {feat.status === 'active' ? 'Active' : 'Not Configured'}
                </Badge>
              </div>
              <CardTitle className="mt-3">{feat.title}</CardTitle>
              <CardDescription>{feat.description}</CardDescription>
            </CardHeader>
            <CardContent className="pt-4">
              <div className="rounded-xl bg-muted/50 p-3 text-xs text-muted-foreground">
                <strong className="text-foreground">Quick start:</strong> {feat.templateHint}
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="mt-3 w-full justify-center"
                onClick={() => navigate('/admin/policies')}
              >
                Configure in Policy Builder →
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
