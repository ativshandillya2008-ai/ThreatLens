import { Shield, AlertTriangle, Lock, Globe, Bot, CheckCircle2, ArrowRight } from 'lucide-react'
import { getApiUrl } from '../api/client'

export default function LoginPage() {
  const urlParams = new URLSearchParams(window.location.search)
  const error = urlParams.get('error')

  const errorMessages: Record<string, string> = {
    oauth_denied: 'Access was denied by Google during consent approval.',
    access_denied: 'Google blocked sign-in because your Gmail address is not added to "Test Users" in Google Cloud Console. Add your email under Google Cloud Console -> APIs & Services -> OAuth consent screen -> Test users.',
    token_exchange_failed: 'Failed to complete server-side token exchange with Google OAuth.',
    incomplete_token_response: 'Google OAuth response did not include necessary token claims.',
    userinfo_failed: 'Unable to retrieve your Google profile information.',
    no_email: 'No email address associated with this Google account.',
  }

  const errorMessage = error ? errorMessages[error] || `Authentication failed: ${error.replace(/_/g, ' ')}` : null

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col items-center justify-center p-6 selection:bg-blue-100 selection:text-blue-900">
      <div className="w-full max-w-lg space-y-6">
        {/* Header Branding */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center h-14 w-14 rounded-2xl bg-blue-50 border border-blue-100 p-2.5 text-blue-600 shadow-sm">
            <Shield className="h-8 w-8" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 tracking-tight">ThreatLens Email Threat Intelligence</h1>
            <p className="text-slate-500 text-sm mt-1 max-w-md mx-auto">
              Automated Gmail threat detection, forensic geolocation, and agentic AI assistant.
            </p>
          </div>
        </div>

        {/* Error Banner */}
        {errorMessage && (
          <div className="flex items-start gap-3 p-4 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800 shadow-sm">
            <AlertTriangle className="h-4 w-4 text-rose-600 mt-0.5 flex-shrink-0" />
            <div className="flex-1">
              <span className="font-semibold text-rose-900">Authentication Error: </span>
              <span>{errorMessage}</span>
            </div>
          </div>
        )}

        {/* Main Card */}
        <div className="bg-white border border-slate-200 rounded-2xl p-7 shadow-sm space-y-6">
          <div className="space-y-1">
            <h2 className="text-sm font-semibold text-slate-900">Connect Your Mailbox</h2>
            <p className="text-xs text-slate-500">
              Authorize ThreatLens to inspect incoming messages, detect security threats, and enable autonomous agent capabilities.
            </p>
          </div>

          {/* Feature Matrix */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80 space-y-1">
              <div className="flex items-center gap-1.5 text-blue-700 font-medium">
                <Bot className="h-3.5 w-3.5 text-blue-600" />
                <span>Agentic AI Assistant</span>
              </div>
              <p className="text-[11px] text-slate-600 leading-snug">Review, summarize, draft, and triage emails interactively</p>
            </div>

            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80 space-y-1">
              <div className="flex items-center gap-1.5 text-blue-700 font-medium">
                <Shield className="h-3.5 w-3.5 text-blue-600" />
                <span>Deep Threat Analysis</span>
              </div>
              <p className="text-[11px] text-slate-600 leading-snug">Detects phishing lures, malware links, & executive impersonation</p>
            </div>

            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80 space-y-1">
              <div className="flex items-center gap-1.5 text-blue-700 font-medium">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                <span>RFC Authentication</span>
              </div>
              <p className="text-[11px] text-slate-600 leading-snug">Strict verification of SPF, DKIM, and DMARC alignment</p>
            </div>

            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200/80 space-y-1">
              <div className="flex items-center gap-1.5 text-blue-700 font-medium">
                <Globe className="h-3.5 w-3.5 text-indigo-600" />
                <span>Forensic Geolocation</span>
              </div>
              <p className="text-[11px] text-slate-600 leading-snug">Received hop tracing & sender IP threat intelligence</p>
            </div>
          </div>

          {/* Privacy & Security Note */}
          <div className="flex items-start gap-2.5 p-3 bg-blue-50/70 border border-blue-100 rounded-xl text-[11px] text-slate-700 leading-relaxed">
            <Lock className="h-4 w-4 text-blue-600 flex-shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-900">Enterprise Privacy: </span>
              OAuth tokens are Fernet-encrypted at rest. Analysis is performed securely via Google Gemini Flash.
            </div>
          </div>

          {/* Connect Button */}
          <a
            href={getApiUrl('/auth/login')}
            className="flex items-center justify-center gap-3 w-full py-3 px-5 bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm rounded-xl shadow-sm hover:shadow transition-all group"
          >
            {/* Google G Logo SVG */}
            <svg className="h-4 w-4" viewBox="0 0 24 24">
              <path
                fill="#FFFFFF"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#FFFFFF"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FFFFFF"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#FFFFFF"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>Connect with Gmail</span>
            <ArrowRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" />
          </a>

          <p className="text-[11px] text-slate-400 text-center">
            Standard Google OAuth 2.0 consent with PKCE verification.
          </p>
        </div>
      </div>
    </div>
  )
}
