import { useState, useRef, useEffect } from 'react'
import {
  Bot,
  Send,
  Sparkles,
  Shield,
  Mail,
  FileText,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Terminal,
  User,
  ShieldAlert,
  Edit3
} from 'lucide-react'
import { api, AgentMessage, UserInfo } from '../api/client'
import Navbar from '../components/Navbar'

interface Props {
  user: UserInfo
}

export default function AgentPage({ user }: Props) {
  const [messages, setMessages] = useState<AgentMessage[]>([
    {
      role: 'assistant',
      content:
        `Hello ${user.name || user.email.split('@')[0]}! I am your **ThreatLens Threat Agent**.\n\n` +
        `I am connected directly to your Gmail account and the ThreatLens Forensic Threat Engine. ` +
        `Like Claude, I can search your mailbox, summarize incoming messages, draft replies, and ` +
        `specifically **detect whether any message is a threat** by evaluating SPF/DKIM/DMARC authentication, ` +
        `IP geolocation routes, and Gemini content heuristics.\n\n` +
        `How can I assist you with your inbox security today?`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const chatEndRef = useRef<HTMLDivElement>(null)

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages, loading])

  const handleSend = async (customPrompt?: string) => {
    const promptToSend = (customPrompt || input).trim()
    if (!promptToSend || loading) return

    const userMessage: AgentMessage = {
      role: 'user',
      content: promptToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    const updated = [...messages, userMessage]
    setMessages(updated)
    setInput('')
    setLoading(true)

    try {
      const res = await api.agent.chat(
        updated.map(m => ({ role: m.role, content: m.content }))
      )

      const assistantMsg: AgentMessage = {
        role: 'assistant',
        content: res.response,
        tools_called: res.tools_called,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }

      setMessages(prev => [...prev, assistantMsg])
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: `I encountered an error communicating with the agentic engine: ${String(err)}`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ])
    } finally {
      setLoading(false)
    }
  }

  const promptSuggestions = [
    {
      label: 'Scan recent emails',
      prompt: 'Inspect my last 5 emails and tell me if any pose a security threat.',
      icon: ShieldAlert,
    },
    {
      label: 'Analyze latest email',
      prompt: 'Fetch the most recent email and provide a forensic threat assessment.',
      icon: Shield,
    },
    {
      label: 'Summarize unread',
      prompt: 'Summarize my unread emails and highlight if any request sensitive action.',
      icon: FileText,
    },
    {
      label: 'Check quarantined',
      prompt: 'List any emails that are currently quarantined and explain why.',
      icon: AlertTriangle,
    },
  ]

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col selection:bg-blue-600 selection:text-white">
      <Navbar user={user} onLogout={() => (window.location.href = '/')} />

      <div className="flex-1 max-w-4xl mx-auto px-4 py-6 w-full flex flex-col">
        {/* Agent Header Banner */}
        <div className="bg-white border border-slate-200 rounded-2xl p-4 mb-4 shadow-sm flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-sm">
              <Bot className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold text-slate-900">ThreatLens Threat Agent</h1>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 font-medium">
                  Claude-like Connector
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Connected to Gmail ({user.email}) — AI Threat Detection & Analysis
              </p>
            </div>
          </div>

          <div className="hidden sm:flex items-center gap-2 text-xs text-slate-500">
            <span className="h-2 w-2 rounded-full bg-emerald-500" />
            <span>Ready for Analysis</span>
          </div>
        </div>

        {/* Chat History Box */}
        <div className="flex-1 bg-white border border-slate-200 rounded-2xl p-5 shadow-sm overflow-y-auto space-y-4 min-h-[420px] max-h-[62vh]">
          {messages.map((m, idx) => (
            <div
              key={idx}
              className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {m.role === 'assistant' && (
                <div className="flex-shrink-0 h-8 w-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700">
                  <Bot className="h-4 w-4" />
                </div>
              )}

              <div
                className={`max-w-2xl rounded-2xl px-4 py-3 text-xs leading-relaxed ${
                  m.role === 'user'
                    ? 'bg-blue-600 text-white rounded-tr-none shadow-sm'
                    : 'bg-slate-50 text-slate-800 border border-slate-200 rounded-tl-none'
                }`}
              >
                {/* Tools executed badge */}
                {m.tools_called && m.tools_called.length > 0 && (
                  <div className="mb-2.5 space-y-1">
                    {m.tools_called.map((t, tidx) => (
                      <div
                        key={tidx}
                        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-white text-slate-600 border border-slate-200 text-[10px] font-mono mr-1.5"
                      >
                        <Terminal className="h-3 w-3 text-blue-600" />
                        <span>Tool: {t.tool}</span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="whitespace-pre-wrap font-sans">
                  {m.content}
                </div>

                {m.timestamp && (
                  <div
                    className={`text-[10px] mt-1.5 font-mono ${
                      m.role === 'user' ? 'text-blue-100 text-right' : 'text-slate-400'
                    }`}
                  >
                    {m.timestamp}
                  </div>
                )}
              </div>

              {m.role === 'user' && (
                <div className="flex-shrink-0 h-8 w-8 rounded-lg bg-slate-200 flex items-center justify-center text-slate-700 text-xs font-bold">
                  {user.name ? user.name.charAt(0).toUpperCase() : user.email.charAt(0).toUpperCase()}
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex items-center gap-3">
              <div className="h-8 w-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700">
                <Bot className="h-4 w-4" />
              </div>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-2xl text-xs text-slate-600 flex items-center gap-2">
                <RefreshCw className="h-3.5 w-3.5 animate-spin text-blue-600" />
                <span>ThreatLens Agent is accessing your mailbox & analyzing threat parameters...</span>
              </div>
            </div>
          )}

          <div ref={chatEndRef} />
        </div>

        {/* Suggestion Chips */}
        <div className="flex items-center gap-2 py-3 overflow-x-auto text-xs">
          <span className="text-[11px] text-slate-500 font-medium flex-shrink-0">Suggested:</span>
          {promptSuggestions.map((item, i) => (
            <button
              key={i}
              onClick={() => handleSend(item.prompt)}
              disabled={loading}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 hover:border-blue-300 transition-colors flex-shrink-0 text-[11px]"
            >
              <item.icon className="h-3 w-3 text-blue-600" />
              <span>{item.label}</span>
            </button>
          ))}
        </div>

        {/* Input Form */}
        <form onSubmit={e => { e.preventDefault(); handleSend(); }} className="relative flex items-center">
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Ask ThreatLens Threat Agent (e.g. 'Is the latest email from PayPal phishing?')"
            className="w-full bg-white border border-slate-300 rounded-2xl pl-4 pr-12 py-3 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 shadow-sm"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="absolute right-2 p-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-40 transition-colors"
            title="Send prompt"
          >
            <Send className="h-4 w-4" />
          </button>
        </form>
      </div>
    </div>
  )
}
