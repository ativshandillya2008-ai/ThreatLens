/**
 * Typed API client for the ThreatLens Email Threat Detection backend.
 * All requests are made to the same origin (proxied to :8088 in dev).
 *
 * CSRF protection: This client fetches a CSRF token from /api/csrf-token
 * on first use and attaches it as X-CSRF-Token on all state-changing
 * (non-GET) requests. This defends against CSRF attacks where a malicious
 * page tries to trigger override/logout actions via the user's session cookie.
 */

export interface ThreatInfo {
  score: number | null;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | null;
  analyzed: boolean;
  threat_id: string | null;
  geo_lat?: number | null;
  geo_lon?: number | null;
  geo_country?: string | null;
  geo_org?: string | null;
  geo_city?: string | null;
  ip?: string | null;
  detected_language?: string | null;
  language_code?: string | null;
}

export interface EmailSummary {
  id: string;
  threadId: string;
  subject: string;
  from: string;
  date: string;
  snippet: string;
  labelIds: string[];
  threat: ThreatInfo;
}

export interface GeoHop {
  ip: string;
  country: string;
  country_code: string;
  city: string;
  asn: string;
  org: string;
  isp?: string;
  lat?: number | null;
  lon?: number | null;
  cardinal_coords?: string;
  threat_score?: number;
  threat_tier?: {
    tier: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe';
    score: number;
    color: string;
    bg_color: string;
    border_color: string;
    label: string;
    typical: string;
  };
}

export interface ThreatDetail {
  id: string;
  message_id: string;
  subject: string;
  sender: string;
  received_at: string | null;
  analyzed_at: string;
  spf: string;
  dkim: string;
  dmarc: string;
  auth_score: number;
  geo_country: string | null;
  geo_asn: string | null;
  geo_org: string | null;
  geo_lat?: number | null;
  geo_lon?: number | null;
  geo_mismatch: boolean;
  geo_score: number;
  geo_hops: GeoHop[];
  llm_score: number;
  llm_threat_type: string;
  llm_reasoning: string[];
  llm_suspicious_phrases: string[];
  urls_checked: string[];
  unsafe_urls: Record<string, string>;
  url_score: number;
  final_score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  quarantined: boolean;
  detected_language?: string | null;
  language_code?: string | null;
  raw_headers?: string;
  overrides?: Array<{
    id: string;
    action: string;
    reason: string | null;
    override_at: string;
  }>;
}

export interface MessagesResponse {
  messages: EmailSummary[];
  nextPageToken: string | null;
  scanning?: boolean;
  unscoredCount?: number;
}

export interface ThreatsResponse {
  threats: ThreatDetail[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ThreatStats {
  LOW: number;
  MEDIUM: number;
  HIGH: number;
  avg_scores: {
    LOW?: number;
    MEDIUM?: number;
    HIGH?: number;
  };
}

export interface WatchSetupResponse {
  status: string;
  watch: {
    historyId?: string;
    expiration?: string;
    [key: string]: unknown;
  };
}

export interface UserInfo {
  email: string;
  name: string;
  picture: string;
}

export interface AgentMessage {
  id?: string;
  role: 'user' | 'assistant';
  content: string;
  tools_called?: Array<{ tool: string; [key: string]: unknown }>;
  timestamp?: string;
  created_at?: string;
}

export interface AgentChatResponse {
  response: string;
  tools_called: Array<{ tool: string; [key: string]: unknown }>;
  authenticated: boolean;
  session_id?: string;
}

export interface AgentSessionSummary {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
  last_message?: string | null;
}

export interface AgentSessionDetail {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
  messages: AgentMessage[];
}

export interface GeoLookupResponse {
  ip: string;
  country: string;
  country_code: string;
  city: string;
  lat: number;
  lon: number;
  cardinal_coords: string;
  org: string;
  asn: string;
  isp: string;
  role: string;
  confidence: number;
  confidence_statement: string;
  threat_score: number;
  threat_tier: {
    tier: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe';
    score: number;
    color: string;
    bg_color: string;
    border_color: string;
    label: string;
    typical: string;
  };
}

export interface GeoReverseResponse {
  lat: number;
  lon: number;
  city: string;
  region?: string;
  country: string;
  country_code: string;
  postcode?: string;
  display_name: string;
  cardinal_coords: string;
}

// ── CSRF token management ──────────────────────────────────────────────────
// Fetched once per session; attached as X-CSRF-Token on all mutating requests.
let _csrfToken: string | null = null;

async function getCsrfToken(): Promise<string> {
  if (_csrfToken) return _csrfToken;
  const response = await fetch('/api/csrf-token', { credentials: 'include' });
  if (!response.ok) throw new Error('Failed to fetch CSRF token');
  const data = await response.json();
  _csrfToken = data.csrf_token as string;
  return _csrfToken;
}

/** Invalidate the cached CSRF token (e.g., after logout). */
export function invalidateCsrfToken(): void {
  _csrfToken = null;
}

// ── Core fetch wrapper ─────────────────────────────────────────────────────
async function apiFetch<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const method = (options?.method ?? 'GET').toUpperCase();
  const isMutating = !['GET', 'HEAD', 'OPTIONS'].includes(method);

  const extraHeaders: Record<string, string> = {};
  if (isMutating) {
    // Attach CSRF token for state-changing requests
    extraHeaders['X-CSRF-Token'] = await getCsrfToken();
  }

  const response = await fetch(path, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers as Record<string, string> ?? {}),
      ...extraHeaders,
    },
    ...options,
  });

  if (!response.ok) {
    // If CSRF token is stale, invalidate and let the caller retry
    if (response.status === 403) {
      invalidateCsrfToken();
    }
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error((error as { detail: string }).detail || `HTTP ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export const api = {
  auth: {
    me: () => apiFetch<UserInfo>('/auth/me'),
    logout: () => {
      const result = apiFetch<{ status: string }>('/auth/logout', { method: 'POST' });
      invalidateCsrfToken(); // Clear token after logout
      return result;
    },
  },

  gmail: {
    messages: (params?: {
      q?: string;
      max_results?: number;
      page_token?: string;
      include_spam_trash?: boolean;
    }) => {
      const qs = new URLSearchParams();
      if (params?.q) qs.set('q', params.q);
      if (params?.max_results) qs.set('max_results', String(params.max_results));
      if (params?.page_token) qs.set('page_token', params.page_token);
      if (params?.include_spam_trash) qs.set('include_spam_trash', 'true');
      return apiFetch<MessagesResponse>(`/api/gmail/messages?${qs}`);
    },
    message: (id: string) =>
      apiFetch<{ message: unknown; threat: ThreatDetail | null }>(
        `/api/gmail/messages/${id}`
      ),
    setupWatch: () => apiFetch<WatchSetupResponse>('/api/gmail/setup-watch'),
    scan: (maxResults: number = 25) =>
      apiFetch<{
        status: string;
        queued: number;
        unscored_count: number;
        already_scored: number;
        total: number;
      }>(`/api/gmail/scan?max_results=${maxResults}`, { method: 'POST' }),
    scanStatus: () =>
      apiFetch<{ scanning: boolean; active_count: number }>('/api/gmail/scan-status'),
  },

  threats: {
    list: (params?: {
      severity?: string;
      sender?: string;
      date_from?: string;
      date_to?: string;
      page?: number;
      page_size?: number;
    }) => {
      const qs = new URLSearchParams();
      if (params?.severity) qs.set('severity', params.severity);
      if (params?.sender) qs.set('sender', params.sender);
      if (params?.date_from) qs.set('date_from', params.date_from);
      if (params?.date_to) qs.set('date_to', params.date_to);
      if (params?.page) qs.set('page', String(params.page));
      if (params?.page_size) qs.set('page_size', String(params.page_size));
      return apiFetch<ThreatsResponse>(`/api/threats/?${qs}`);
    },
    get: (id: string, includeHeaders: boolean = false) => {
      const qs = includeHeaders ? '?include_headers=true' : '';
      return apiFetch<ThreatDetail>(`/api/threats/${id}${qs}`);
    },
    override: (id: string, action: 'release' | 'confirm', reason?: string) =>
      apiFetch<{ status: string; action: string; override_id: string }>(`/api/threats/${id}/override`, {
        method: 'POST',
        body: JSON.stringify({ action, reason: reason ?? '' }),
      }),
    stats: () => apiFetch<ThreatStats>('/api/threats/stats/summary'),
  },

  agent: {
    chat: (
      payload:
        | { messages?: AgentMessage[]; prompt?: string; session_id?: string }
        | AgentMessage[]
    ) => {
      const body = Array.isArray(payload) ? { messages: payload } : payload;
      return apiFetch<AgentChatResponse>('/api/agent/chat', {
        method: 'POST',
        body: JSON.stringify(body),
      });
    },
    listSessions: () =>
      apiFetch<{ sessions: AgentSessionSummary[] }>('/api/agent/sessions'),
    getSession: (sessionId: string) =>
      apiFetch<AgentSessionDetail>(`/api/agent/sessions/${sessionId}`),
    createSession: (title?: string) =>
      apiFetch<AgentSessionDetail>('/api/agent/sessions', {
        method: 'POST',
        body: JSON.stringify({ title }),
      }),
    deleteSession: (sessionId: string) =>
      apiFetch<{ status: string; id: string }>(`/api/agent/sessions/${sessionId}`, {
        method: 'DELETE',
      }),
    clearAllSessions: () =>
      apiFetch<{ status: string }>('/api/agent/sessions', {
        method: 'DELETE',
      }),
  },

  geo: {
    lookup: (ip: string) =>
      apiFetch<GeoLookupResponse>('/api/geo/lookup', {
        method: 'POST',
        body: JSON.stringify({ ip }),
      }),
    reverse: (lat: number, lon: number) =>
      apiFetch<GeoReverseResponse>('/api/geo/reverse', {
        method: 'POST',
        body: JSON.stringify({ lat, lon }),
      }),
  },
};

