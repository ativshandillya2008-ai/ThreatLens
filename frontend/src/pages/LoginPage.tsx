import { useState } from 'react'
import {
  Shield,
  AlertTriangle,
  Lock,
  Globe,
  Bot,
  CheckCircle2,
  ArrowRight,
  HelpCircle,
  KeyRound,
  ShieldCheck,
  Zap,
  Info,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { getApiUrl } from '../api/client'

export default function LoginPage() {
  const urlParams = new URLSearchParams(window.location.search)
  const error = urlParams.get('error')
  const [showConsentGuide, setShowConsentGuide] = useState(false)

  const errorMessages: Record<string, { title: string; message: string; fix: string }> = {
    session_expired: {
      title: 'Session Expired',
      message: 'Your authenticated Google session has expired.',
      fix: 'Please sign in with Google again to re-authorize ThreatLens.',
    },
    access_denied: {
      title: 'Google Access Blocked (Testing Mode)',
      message:
        'Google blocked the sign-in because your Gmail address is not yet added to "Test Users" in Google Cloud Console, or the app has not been published to "In Production".',
      fix: 'To allow ANYONE to use your website: Open Google Cloud Console -> APIs & Services -> OAuth consent screen -> Click "Publish App". Alternatively, add your email under "Test users".',
    },
    oauth_denied: {
      title: 'Authorization Cancelled',
      message: 'Access was cancelled or denied during the Google consent screen.',
      fix: 'To use ThreatLens, you must grant permission for ThreatLens to inspect your mailbox for security threats.',
    },
    token_exchange_failed: {
      title: 'Token Exchange Failed',
      message: 'The server could not exchange the authorization code with Google.',
      fix: 'Verify GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in backend .env.',
    },
    incomplete_token_response: {
      title: 'Token Incomplete',
      message: 'Google did not return an authorization token.',
      fix: 'Please sign in again and ensure all consent checkboxes are selected.',
    },
    userinfo_failed: {
      title: 'Profile Fetch Error',
      message: 'Unable to retrieve your Google profile info.',
      fix: 'Please try signing in again in a moment.',
    },
    no_email: {
      title: 'No Email Associated',
      message: 'Your Google account does not report an email address.',
      fix: 'Ensure your Google account profile has a primary email address.',
    },
  }

  const errorDetail = error ? errorMessages[error] || {
    title: 'Authentication Error',
    message: `Sign-in could not be completed: ${error.replace(/_/g, ' ')}`,
    fix: 'Please retry signing in with your Google account.',
  } : null

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-4 sm:p-6 selection:bg-blue-600 selection:text-white relative overflow-hidden">
      {/* Subtle Background Glow Elements */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-blue-600/10 blur-[130px] rounded-full pointer-events-none" />
      <div className="absolute bottom-10 right-1/4 w-[400px] h-[250px] bg-indigo-600/10 blur-[100px] rounded-full pointer-events-none" />

      <div className="w-full max-w-xl space-y-6 relative z-10">
        {/* Top Branding */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-blue-950/80 border border-blue-500/30 p-3 text-blue-400 shadow-lg shadow-blue-500/10 backdrop-blur-md">
            <Shield className="h-9 w-9 text-blue-400" />
          </div>
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-300 text-xs font-medium mb-2">
              <ShieldCheck className="h-3.5 w-3.5 text-blue-400" />
              <span>AI-Powered Forensic Email Threat Detection</span>
            </div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">ThreatLens</h1>
            <p className="text-slate-400 text-sm mt-1.5 max-w-md mx-auto leading-relaxed">
              Real-time Gmail threat inspection, hop-by-hop IP geolocation, and agentic AI security forensics.
            </p>
          </div>
        </div>

        {/* Strict No Guest Mode Badge */}
        <div className="flex items-center justify-between p-3.5 bg-slate-900/90 border border-amber-500/30 rounded-2xl text-xs backdrop-blur-md">
          <div className="flex items-center gap-2.5 text-amber-300">
            <KeyRound className="h-4 w-4 text-amber-400 flex-shrink-0" />
            <span className="font-semibold">Google Sign-In Required</span>
            <span className="text-slate-400">•</span>
            <span className="text-slate-400">No Guest Mode</span>
          </div>
          <span className="px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] font-mono font-medium">
            LIVE MAILBOX ONLY
          </span>
        </div>

        {/* Error Alert Card */}
        {errorDetail && (
          <div className="p-4 bg-rose-950/60 border border-rose-500/40 rounded-2xl text-xs text-rose-200 shadow-lg backdrop-blur-md space-y-2">
            <div className="flex items-center gap-2 font-bold text-rose-300">
              <AlertTriangle className="h-4 w-4 text-rose-400 flex-shrink-0" />
              <span>{errorDetail.title}</span>
            </div>
            <p className="text-slate-300 text-[11px] leading-relaxed pl-6">
              {errorDetail.message}
            </p>
            <div className="pl-6 pt-1 text-[11px] text-amber-300/90 flex items-start gap-1.5 border-t border-rose-900/50 mt-2">
              <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5 text-amber-400" />
              <span>{errorDetail.fix}</span>
            </div>
          </div>
        )}

        {/* Main Authentication Card */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-3xl p-7 sm:p-8 shadow-2xl backdrop-blur-xl space-y-6">
          <div className="space-y-1.5 text-center sm:text-left">
            <h2 className="text-lg font-bold text-white tracking-tight">
              Connect Your Google Account
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Anyone with a Google account can use ThreatLens. Sign in with Google to authorize mailbox threat inspection, phishing quarantine, and AI agent capabilities.
            </p>
          </div>

          {/* Official Google Sign-In Button */}
          <a
            href={getApiUrl('/auth/login')}
            id="google-signin-button"
            className="flex items-center justify-center gap-3 w-full py-3.5 px-6 bg-white hover:bg-slate-100 text-slate-900 font-semibold text-sm rounded-2xl shadow-md hover:shadow-xl transition-all duration-200 group active:scale-[0.99] border border-slate-200"
          >
            {/* Authentic 4-Color Google G SVG Logo */}
            <svg className="h-5 w-5 flex-shrink-0" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>Sign in with Google to Connect Gmail</span>
            <ArrowRight className="h-4 w-4 text-slate-500 group-hover:translate-x-1 transition-transform" />
          </a>

          {/* No Guest Mode Explanation Accordion */}
          <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-2xl text-[11px] text-slate-400 space-y-1.5">
            <div className="flex items-center gap-2 text-slate-300 font-semibold">
              <Zap className="h-3.5 w-3.5 text-blue-400" />
              <span>Why is there no Guest Mode?</span>
            </div>
            <p className="leading-relaxed text-slate-400">
              ThreatLens analyzes actual email headers (SPF/DKIM/DMARC), received network hops, and email payloads directly from your Gmail account. Because live mailbox connectivity requires active Google OAuth authorization, guest mode is completely disabled.
            </p>
          </div>

          {/* Feature Matrix */}
          <div className="grid grid-cols-2 gap-2.5 text-xs">
            <div className="p-3 bg-slate-950/40 rounded-xl border border-slate-800/80 space-y-1">
              <div className="flex items-center gap-1.5 text-blue-400 font-medium">
                <Bot className="h-3.5 w-3.5 text-blue-400" />
                <span>Agentic AI Assistant</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">
                Search, summarize, triage, and draft safe replies interactively
              </p>
            </div>

            <div className="p-3 bg-slate-950/40 rounded-xl border border-slate-800/80 space-y-1">
              <div className="flex items-center gap-1.5 text-blue-400 font-medium">
                <Shield className="h-3.5 w-3.5 text-blue-400" />
                <span>Deep Threat Analysis</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">
                Detects phishing lures, malware links, & executive impersonation
              </p>
            </div>

            <div className="p-3 bg-slate-950/40 rounded-xl border border-slate-800/80 space-y-1">
              <div className="flex items-center gap-1.5 text-emerald-400 font-medium">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                <span>RFC Authentication</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">
                Strict verification of SPF, DKIM, and DMARC alignment
              </p>
            </div>

            <div className="p-3 bg-slate-950/40 rounded-xl border border-slate-800/80 space-y-1">
              <div className="flex items-center gap-1.5 text-indigo-400 font-medium">
                <Globe className="h-3.5 w-3.5 text-indigo-400" />
                <span>Forensic Geolocation</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">
                Received hop tracing & sender IP threat intelligence
              </p>
            </div>
          </div>

          {/* Privacy & Security Note */}
          <div className="flex items-start gap-2.5 p-3 bg-blue-950/30 border border-blue-900/40 rounded-2xl text-[11px] text-slate-300 leading-relaxed">
            <Lock className="h-4 w-4 text-blue-400 flex-shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-white">Enterprise Privacy: </span>
              OAuth tokens are Fernet-encrypted at rest. Email bodies are never stored persistently on the server.
            </div>
          </div>

          {/* Expandable Universal Access Guide */}
          <div className="border-t border-slate-800 pt-3">
            <button
              onClick={() => setShowConsentGuide(!showConsentGuide)}
              className="w-full flex items-center justify-between text-[11px] text-slate-400 hover:text-blue-400 transition-colors py-1"
            >
              <span className="inline-flex items-center gap-1.5 font-medium">
                <HelpCircle className="h-3.5 w-3.5" />
                <span>How Anyone Can Sign In & Google Consent Screen Guide</span>
              </span>
              {showConsentGuide ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            </button>

            {showConsentGuide && (
              <div className="mt-3 p-4 bg-slate-950 border border-slate-800 rounded-2xl text-[11px] text-slate-300 space-y-2.5 animate-fadeIn">
                <div className="font-semibold text-white flex items-center gap-1.5">
                  <Info className="h-3.5 w-3.5 text-blue-400" />
                  <span>Google "Unverified App" Screen Instructions</span>
                </div>
                <p className="text-slate-400 leading-relaxed">
                  When signing in to self-hosted or testing deployments, Google displays a standard warning saying <em>"Google hasn't verified this app"</em>:
                </p>
                <ol className="list-decimal pl-4 space-y-1.5 text-slate-300">
                  <li>On the Google warning page, click <strong className="text-white">"Advanced"</strong> in the bottom left.</li>
                  <li>Click <strong className="text-white">"Go to ThreatLens (unsafe)"</strong> to proceed.</li>
                  <li>Select the checkboxes allowing ThreatLens to view your email messages, then click <strong className="text-white">"Continue"</strong>.</li>
                </ol>
                <div className="p-2.5 bg-blue-950/40 border border-blue-800/40 rounded-xl text-[10px] text-blue-300">
                  <strong>For Admins / Cloud Hosting:</strong> In Google Cloud Console under <em>OAuth consent screen</em>, set Publishing Status to <strong>In Production</strong> so any user on the internet can sign in.
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer info */}
        <p className="text-[11px] text-slate-500 text-center font-mono">
          Protected by Google OAuth 2.0 PKCE • RFC 7636 • AES-128 Fernet Tokens
        </p>
      </div>
    </div>
  )
}

