import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Bot,
  Send,
  Shield,
  FileText,
  AlertTriangle,
  RefreshCw,
  Terminal,
  ShieldAlert,
  Plus,
  MessageSquare,
  Trash2,
  Clock,
  X,
  History,
  Sparkles,
  ChevronRight,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { api, AgentMessage, AgentSessionSummary, UserInfo } from '../api/client'
import Navbar from '../components/Navbar'

interface Props {
  user: UserInfo
}

export default function AgentPage({ user }: Props) {
  const getDefaultWelcomeMessage = (): AgentMessage => ({
    role: 'assistant',
    content:
      `Hello ${user.name || user.email.split('@')[0]}! I am your **ThreatLens Threat Agent**.\n\n` +
      `I am connected directly to your Gmail account and the ThreatLens Forensic Threat Engine. ` +
      `I can search your mailbox, summarize incoming messages, draft replies, and ` +
      `specifically **detect whether any message is a threat** by evaluating SPF/DKIM/DMARC authentication, ` +
      `IP geolocation routes, and Gemini content heuristics.\n\n` +
      `How can I assist you with your inbox security today?`,
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  })

  const [sessions, setSessions] = useState<AgentSessionSummary[]>([])
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null)
  const [sessionsLoading, setSessionsLoading] = useState<boolean>(true)
  const [isSidebarOpen, setIsSidebarOpen] = useState<boolean>(false)
  const [messages, setMessages] = useState<AgentMessage[]>([getDefaultWelcomeMessage()])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const chatEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages, loading])

  // Select a session and load its messages
  const selectSession = async (sessionId: string) => {
    try {
      setActiveSessionId(sessionId)
      setIsSidebarOpen(false)
      const detail = await api.agent.getSession(sessionId)
      if (detail.messages && detail.messages.length > 0) {
        setMessages(
          detail.messages.map(m => ({
            id: m.id,
            role: m.role,
            content: m.content,
            tools_called: m.tools_called,
            timestamp: m.created_at
              ? new Date(m.created_at).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                })
              : undefined,
          }))
        )
      } else {
        setMessages([getDefaultWelcomeMessage()])
      }
    } catch (e) {
      console.error('Failed to load session details:', e)
    }
  }

  // Load list of sessions on initial load
  const loadSessions = useCallback(async (selectInitial: boolean = true) => {
    try {
      setSessionsLoading(true)
      const data = await api.agent.listSessions()
      const list = data.sessions || []
      setSessions(list)

      if (selectInitial && list.length > 0) {
        await selectSession(list[0].id)
      }
    } catch (e) {
      console.error('Failed to list sessions:', e)
    } finally {
      setSessionsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadSessions(true)
  }, [loadSessions])

  // Start a new conversation
  const handleNewChat = () => {
    setActiveSessionId(null)
    setMessages([getDefaultWelcomeMessage()])
    setIsSidebarOpen(false)
    inputRef.current?.focus()
  }

  // Delete a session
  const handleDeleteSession = async (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await api.agent.deleteSession(sessionId)
      const remaining = sessions.filter(s => s.id !== sessionId)
      setSessions(remaining)

      if (activeSessionId === sessionId) {
        if (remaining.length > 0) {
          await selectSession(remaining[0].id)
        } else {
          handleNewChat()
        }
      }
    } catch (err) {
      console.error('Failed to delete session:', err)
    }
  }

  // Clear all sessions
  const handleClearAllSessions = async () => {
    if (!window.confirm('Are you sure you want to clear all chat history?')) return
    try {
      await api.agent.clearAllSessions()
      setSessions([])
      handleNewChat()
    } catch (err) {
      console.error('Failed to clear sessions:', err)
    }
  }

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
      const res = await api.agent.chat({
        prompt: promptToSend,
        session_id: activeSessionId || undefined,
        messages: updated.map(m => ({ role: m.role, content: m.content })),
      })

      const assistantMsg: AgentMessage = {
        role: 'assistant',
        content: res.response,
        tools_called: res.tools_called,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }

      setMessages(prev => [...prev, assistantMsg])

      if (res.session_id) {
        setActiveSessionId(res.session_id)
      }

      // Refresh sidebar list in background to update title and timestamps
      api.agent.listSessions().then(data => {
        setSessions(data.sessions || [])
      })
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

  const formatSessionTime = (dateStr?: string) => {
    if (!dateStr) return ''
    try {
      return formatDistanceToNow(new Date(dateStr), { addSuffix: true })
    } catch {
      return ''
    }
  }

  const activeSessionTitle =
    sessions.find(s => s.id === activeSessionId)?.title || 'New Security Investigation'

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col selection:bg-blue-600 selection:text-white">
      <Navbar user={user} onLogout={() => (window.location.href = '/')} />

      <div className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 w-full flex flex-col">
        {/* Main Workspace with Split Chat & History */}
        <div className="flex-1 flex gap-5 min-h-[620px] max-h-[82vh]">
          {/* Left Sidebar: Chat History (Desktop) */}
          <aside className="w-80 flex-shrink-0 bg-white border border-slate-200 rounded-2xl p-4 shadow-sm hidden md:flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
                <MessageSquare className="h-4 w-4 text-blue-600" />
                <span>Chat History</span>
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-mono font-medium">
                  {sessions.length}
                </span>
              </div>

              <button
                onClick={handleNewChat}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-all"
                title="Start a new chat conversation"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>New Chat</span>
              </button>
            </div>

            {/* Sessions List */}
            <div className="flex-1 overflow-y-auto space-y-1 py-3 pr-1">
              {sessionsLoading && sessions.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 gap-2 text-slate-400">
                  <RefreshCw className="h-4 w-4 animate-spin text-blue-600" />
                  <span className="text-xs">Loading conversations...</span>
                </div>
              ) : sessions.length === 0 ? (
                <div className="text-center py-12 px-2 text-slate-400">
                  <MessageSquare className="h-8 w-8 mx-auto mb-2 text-slate-300" />
                  <p className="text-xs font-medium text-slate-600">No saved chats yet</p>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Conversations with ThreatLens Agent will automatically save here.
                  </p>
                </div>
              ) : (
                sessions.map(s => {
                  const isActive = s.id === activeSessionId
                  return (
                    <div
                      key={s.id}
                      onClick={() => selectSession(s.id)}
                      className={`group relative flex items-start gap-2.5 p-2.5 rounded-xl cursor-pointer border transition-all ${
                        isActive
                          ? 'bg-blue-50/80 border-blue-200 text-blue-950 shadow-xs'
                          : 'bg-white hover:bg-slate-50 border-transparent hover:border-slate-200 text-slate-700'
                      }`}
                    >
                      <div
                        className={`mt-0.5 p-1.5 rounded-lg flex-shrink-0 ${
                          isActive
                            ? 'bg-blue-600 text-white'
                            : 'bg-slate-100 text-slate-500 group-hover:bg-slate-200'
                        }`}
                      >
                        <Bot className="h-3.5 w-3.5" />
                      </div>

                      <div className="flex-1 min-w-0 pr-6">
                        <div className="text-xs font-semibold truncate" title={s.title}>
                          {s.title}
                        </div>
                        <div className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
                          <span>{formatSessionTime(s.updated_at)}</span>
                          <span>•</span>
                          <span>{s.message_count} msgs</span>
                        </div>
                      </div>

                      <button
                        onClick={e => handleDeleteSession(s.id, e)}
                        className="opacity-0 group-hover:opacity-100 absolute right-2 top-2.5 p-1 rounded-lg hover:bg-rose-50 text-slate-400 hover:text-rose-600 transition-all"
                        title="Delete chat session"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  )
                })
              )}
            </div>

            {/* Bottom Controls */}
            {sessions.length > 0 && (
              <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
                <button
                  onClick={handleClearAllSessions}
                  className="text-slate-400 hover:text-rose-600 transition-colors flex items-center gap-1"
                  title="Clear all saved conversations"
                >
                  <Trash2 className="h-3 w-3" />
                  <span>Clear all history</span>
                </button>
                <span className="font-mono text-[10px] text-slate-400">ThreatLens Sync</span>
              </div>
            )}
          </aside>

          {/* Mobile Drawer Overlay */}
          {isSidebarOpen && (
            <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex md:hidden">
              <div className="w-80 max-w-[85vw] bg-white h-full p-4 flex flex-col shadow-xl animate-in slide-in-from-left">
                <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
                    <MessageSquare className="h-4 w-4 text-blue-600" />
                    <span>Chat History</span>
                  </div>
                  <button
                    onClick={() => setIsSidebarOpen(false)}
                    className="p-1 text-slate-400 hover:text-slate-600"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>

                <div className="py-3">
                  <button
                    onClick={handleNewChat}
                    className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl bg-blue-600 text-white text-xs font-semibold shadow-xs"
                  >
                    <Plus className="h-4 w-4" />
                    <span>New Chat</span>
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto space-y-1 pr-1">
                  {sessions.map(s => (
                    <div
                      key={s.id}
                      onClick={() => selectSession(s.id)}
                      className={`flex items-start gap-2.5 p-2.5 rounded-xl cursor-pointer border ${
                        s.id === activeSessionId
                          ? 'bg-blue-50 border-blue-200 text-blue-950 font-semibold'
                          : 'bg-white border-slate-200 text-slate-700'
                      }`}
                    >
                      <Bot className="h-4 w-4 text-blue-600 mt-0.5 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="text-xs truncate">{s.title}</div>
                        <div className="text-[11px] text-slate-400">
                          {formatSessionTime(s.updated_at)}
                        </div>
                      </div>
                      <button
                        onClick={e => handleDeleteSession(s.id, e)}
                        className="p-1 text-slate-400 hover:text-rose-600"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
              <div className="flex-1" onClick={() => setIsSidebarOpen(false)} />
            </div>
          )}

          {/* Right Main Chat Container */}
          <main className="flex-1 min-w-0 flex flex-col bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden">
            {/* Conversation Header */}
            <div className="px-5 py-3.5 border-b border-slate-200 bg-slate-50 flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-2.5 min-w-0">
                <button
                  onClick={() => setIsSidebarOpen(true)}
                  className="md:hidden p-1.5 rounded-xl border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
                  title="Open chat history"
                >
                  <History className="h-4 w-4 text-blue-600" />
                </button>

                <div className="h-8 w-8 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-xs flex-shrink-0">
                  <Bot className="h-4 w-4" />
                </div>

                <div className="min-w-0">
                  <h1 className="text-xs font-bold text-slate-900 truncate" title={activeSessionTitle}>
                    {activeSessionTitle}
                  </h1>
                  <p className="text-[11px] text-slate-400 flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                    <span>Gmail ({user.email}) — AI Threat Engine Active</span>
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleNewChat}
                  className="md:hidden flex items-center gap-1 px-2.5 py-1 rounded-xl bg-blue-600 text-white text-xs font-semibold"
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>New</span>
                </button>

                <div className="hidden sm:flex items-center gap-2 text-[11px] text-slate-500 font-mono bg-white px-2.5 py-1 rounded-xl border border-slate-200">
                  <Clock className="h-3 w-3 text-blue-600" />
                  <span>Persistent History Active</span>
                </div>
              </div>
            </div>

            {/* Chat Messages Box */}
            <div className="flex-1 p-5 overflow-y-auto space-y-4">
              {messages.map((m, idx) => (
                <div
                  key={m.id || idx}
                  className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  {m.role === 'assistant' && (
                    <div className="flex-shrink-0 h-8 w-8 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700 mt-0.5">
                      <Bot className="h-4 w-4" />
                    </div>
                  )}

                  <div
                    className={`max-w-2xl rounded-2xl px-4 py-3 text-xs leading-relaxed ${
                      m.role === 'user'
                        ? 'bg-blue-600 text-white rounded-tr-none shadow-xs'
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

                    <div className="whitespace-pre-wrap font-sans">{m.content}</div>

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
                    <div className="flex-shrink-0 h-8 w-8 rounded-xl bg-slate-200 flex items-center justify-center text-slate-700 text-xs font-bold mt-0.5">
                      {user.name
                        ? user.name.charAt(0).toUpperCase()
                        : user.email.charAt(0).toUpperCase()}
                    </div>
                  )}
                </div>
              ))}

              {loading && (
                <div className="flex items-center gap-3">
                  <div className="h-8 w-8 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700">
                    <Bot className="h-4 w-4" />
                  </div>
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded-2xl text-xs text-slate-600 flex items-center gap-2">
                    <RefreshCw className="h-3.5 w-3.5 animate-spin text-blue-600" />
                    <span>ThreatLens Agent is accessing your mailbox & analyzing parameters...</span>
                  </div>
                </div>
              )}

              <div ref={chatEndRef} />
            </div>

            {/* Suggestion Chips */}
            <div className="px-5 py-2 border-t border-slate-100 bg-slate-50/50 flex items-center gap-2 overflow-x-auto text-xs">
              <span className="text-[11px] text-slate-400 font-medium flex-shrink-0">Suggestions:</span>
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
            <div className="p-4 bg-white border-t border-slate-200">
              <form
                onSubmit={e => {
                  e.preventDefault()
                  handleSend()
                }}
                className="relative flex items-center"
              >
                <input
                  ref={inputRef}
                  type="text"
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  placeholder="Ask ThreatLens Threat Agent (e.g. 'Is the latest email from PayPal phishing?')"
                  className="w-full bg-slate-50 border border-slate-300 rounded-2xl pl-4 pr-12 py-3 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white transition-all shadow-xs"
                />
                <button
                  type="submit"
                  disabled={!input.trim() || loading}
                  className="absolute right-2 p-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-40 transition-colors shadow-xs"
                  title="Send prompt"
                >
                  <Send className="h-4 w-4" />
                </button>
              </form>
            </div>
          </main>
        </div>
      </div>
    </div>
  )
}
