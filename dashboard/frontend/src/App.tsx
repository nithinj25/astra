import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import PacketFeed    from './components/PacketFeed'
import AttackMap     from './components/AttackMap'
import ThreatGraph   from './components/ThreatGraph'
import ThreatIntel   from './components/ThreatIntel'
import ProtocolChart from './components/ProtocolChart'
import SourceTracker from './components/SourceTracker'
import EventDrawer   from './components/EventDrawer'

export interface IDSEvent {
  timestamp:    string
  packet_type:  string
  source:       string
  verdict:      'ALLOW' | 'ALERT' | 'BLOCK'
  threat_score: number
  drone_state:  { armed: boolean; lat: number; lon: number; alt: number; mode: number }
  attack_type:  string | null
  rule:         string
}

// ── Sim actions ────────────────────────────────────────────────────────────────
const SIM_ACTIONS = [
  { id: 'normal', label: 'Normal Flight', variant: 'safe'   },
  { id: 'arm',    label: 'ARM Inject',    variant: 'danger' },
  { id: 'gps',    label: 'GPS Spoof',     variant: 'warn'   },
  { id: 'mode',   label: 'Mode Change',   variant: 'info'   },
  { id: 'all',    label: 'Full Attack',   variant: 'danger' },
  { id: 'stop',   label: 'Stop',          variant: 'muted'  },
] as const

const MODE_NAMES: Record<number, string> = {
  0: 'STAB', 3: 'AUTO', 4: 'GUIDED', 6: 'RTL', 9: 'LAND',
}

// ── Threat level ───────────────────────────────────────────────────────────────
type ThreatLevel = 'SECURE' | 'GUARDED' | 'ELEVATED' | 'HIGH' | 'CRITICAL'

const THREAT_COLOR: Record<ThreatLevel, string> = {
  SECURE:   'text-ds-green',
  GUARDED:  'text-ds-cyan',
  ELEVATED: 'text-ds-amber',
  HIGH:     'text-ds-red',
  CRITICAL: 'text-ds-red',
}
const THREAT_BADGE: Record<ThreatLevel, string> = {
  SECURE:   'border-ds-green/25  bg-green-950/30',
  GUARDED:  'border-ds-cyan/25   bg-cyan-950/30',
  ELEVATED: 'border-ds-amber/25  bg-amber-950/30',
  HIGH:     'border-ds-red/25    bg-red-950/30',
  CRITICAL: 'border-ds-red/40    bg-red-950/50',
}

// ── Tab types ──────────────────────────────────────────────────────────────────
type Tab = 'intel' | 'protocol' | 'sources'

const TABS: { id: Tab; label: string }[] = [
  { id: 'intel',    label: 'Threat Intel'   },
  { id: 'protocol', label: 'Protocol Stats' },
  { id: 'sources',  label: 'Source Tracker' },
]

const MAX_EVENTS = 200
const MAX_SCORES = 120

// ── Sim button style ───────────────────────────────────────────────────────────
function simCls(variant: string, active: boolean, busy: boolean) {
  const base = 'px-3 py-1.5 text-[11px] font-mono border rounded transition-all select-none'
  const cur  = busy ? 'cursor-wait' : 'cursor-pointer'
  type Entry = { b: string; on: string; off: string }
  const M: Record<string, Entry> = {
    safe:   { b: 'border-ds-green/40',  on: 'bg-green-950/60 text-ds-green ring-1 ring-ds-green/40',  off: 'text-ds-green/50  hover:text-ds-green/80'  },
    danger: { b: 'border-ds-red/40',    on: 'bg-red-950/60   text-ds-red   ring-1 ring-ds-red/40',    off: 'text-ds-red/50    hover:text-ds-red/80'    },
    warn:   { b: 'border-ds-amber/40',  on: 'bg-amber-950/60 text-ds-amber ring-1 ring-ds-amber/40',  off: 'text-ds-amber/50  hover:text-ds-amber/80'  },
    info:   { b: 'border-ds-blue/40',   on: 'bg-blue-950/60  text-ds-blue  ring-1 ring-ds-blue/40',   off: 'text-ds-blue/50   hover:text-ds-blue/80'   },
    muted:  { b: 'border-ds-t3/30',     on: 'bg-ds-panel2    text-ds-t1    ring-1 ring-ds-t3/30',     off: 'text-ds-t3        hover:text-ds-t2'        },
  }
  const e = M[variant] ?? M.muted
  return `${base} ${cur} ${e.b} ${active ? e.on : e.off}`
}

// ── Duration formatter ─────────────────────────────────────────────────────────
function fmtDuration(s: number): string {
  const h   = Math.floor(s / 3600)
  const m   = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`
  return `${String(m).padStart(2, '0')}m ${String(sec).padStart(2, '0')}s`
}

export default function App() {
  const [events,        setEvents]        = useState<IDSEvent[]>([])
  const [scores,        setScores]        = useState<{ t: number; v: number }[]>([])
  const [connected,     setConnected]     = useState(false)
  const [flashing,      setFlashing]      = useState(false)
  const [simMode,       setSimMode]       = useState<string>('normal')
  const [simLoading,    setSimLoading]    = useState(false)
  const [pktRate,       setPktRate]       = useState(0)
  const [evtPerMin,     setEvtPerMin]     = useState(0)
  const [sessionSecs,   setSessionSecs]   = useState(0)
  const [activeTab,     setActiveTab]     = useState<Tab>('intel')
  const [selectedEvent, setSelectedEvent] = useState<IDSEvent | null>(null)
  const [droneState,    setDroneState]    = useState<IDSEvent['drone_state']>({
    armed: false, lat: 37.7749, lon: -122.4194, alt: 50, mode: 0,
  })

  const wsRef        = useRef<WebSocket | null>(null)
  const flashRef     = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnRef    = useRef<ReturnType<typeof setTimeout> | null>(null)
  const rateBuf      = useRef<number[]>([])
  const sessionStart = useRef(Date.now())

  const triggerFlash = useCallback(() => {
    setFlashing(true)
    if (flashRef.current) clearTimeout(flashRef.current)
    flashRef.current = setTimeout(() => setFlashing(false), 600)
  }, [])

  // ── Session timer ──────────────────────────────────────────────────────────
  useEffect(() => {
    const iv = setInterval(() => {
      setSessionSecs(Math.floor((Date.now() - sessionStart.current) / 1000))
    }, 1000)
    return () => clearInterval(iv)
  }, [])

  // ── Packet rate + events/min ──────────────────────────────────────────────
  useEffect(() => {
    const iv = setInterval(() => {
      const now = Date.now()
      rateBuf.current = rateBuf.current.filter(t => now - t < 5000)
      setPktRate(rateBuf.current.length / 5)

      const lastMin = rateBuf.current.filter(t => now - t < 60_000).length
      setEvtPerMin(lastMin)
    }, 1000)
    return () => clearInterval(iv)
  }, [])

  // ── WebSocket ──────────────────────────────────────────────────────────────
  const connect = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState < 2) return
    const ws = new WebSocket('ws://localhost:8000/ws')
    wsRef.current = ws

    ws.onopen  = () => setConnected(true)

    ws.onmessage = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data as string)
        if (!data.verdict) return
        const ev = data as IDSEvent

        rateBuf.current.push(Date.now())
        setEvents(prev => [ev, ...prev].slice(0, MAX_EVENTS))
        setDroneState(ev.drone_state)
        setScores(prev => [...prev, { t: Date.now(), v: ev.threat_score }].slice(-MAX_SCORES))

        if (ev.verdict === 'BLOCK') triggerFlash()
      } catch { /* ignore */ }
    }

    ws.onclose = () => {
      setConnected(false)
      wsRef.current = null
      reconnRef.current = setTimeout(connect, 2000)
    }

    ws.onerror = () => ws.close()
  }, [triggerFlash])

  useEffect(() => {
    connect()
    return () => {
      if (reconnRef.current) clearTimeout(reconnRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  // ── Computed ───────────────────────────────────────────────────────────────
  const stats = useMemo(() => {
    const total   = events.length
    const blocked = events.filter(e => e.verdict === 'BLOCK').length
    const alerted = events.filter(e => e.verdict === 'ALERT').length
    const score   = scores.at(-1)?.v ?? 0
    const pct     = (n: number) => total ? `${((n / total) * 100).toFixed(1)}%` : '—'
    return { total, blocked, alerted, score, pct }
  }, [events, scores])

  const threatLevel = useMemo((): ThreatLevel => {
    const r  = events.slice(0, 20)
    const bl = r.filter(e => e.verdict === 'BLOCK').length
    const al = r.filter(e => e.verdict === 'ALERT').length
    const mx = Math.max(0, ...r.map(e => e.threat_score))
    if (bl >= 3 || mx >= 0.70)  return 'CRITICAL'
    if (bl >= 1 || mx >= 0.45)  return 'HIGH'
    if (al >= 2 || mx >= 0.20)  return 'ELEVATED'
    if (al >= 1 || mx >= 0.08)  return 'GUARDED'
    return 'SECURE'
  }, [events])

  // ── Simulation ─────────────────────────────────────────────────────────────
  const startSim = useCallback(async (action: string) => {
    setSimLoading(true)
    try {
      const res = await fetch('/api/simulate', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ action }),
      })
      if (res.ok) setSimMode(action === 'stop' ? 'stopped' : action)
    } catch (err) {
      console.error('[DS] sim error:', err)
    } finally {
      setSimLoading(false)
    }
  }, [])

  // ── Export ─────────────────────────────────────────────────────────────────
  const exportJSON = useCallback(() => {
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `droneshield-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [events])

  const exportCSV = useCallback(() => {
    const header = 'timestamp,verdict,packet_type,source,rule,threat_score,armed,lat,lon,alt,mode'
    const rows   = events.map(e =>
      [
        e.timestamp, e.verdict, e.packet_type, e.source,
        e.rule ?? '', e.threat_score.toFixed(4),
        e.drone_state.armed, e.drone_state.lat.toFixed(6),
        e.drone_state.lon.toFixed(6), e.drone_state.alt.toFixed(1),
        e.drone_state.mode,
      ].join(',')
    )
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `droneshield-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [events])

  // ── Stat cards data ────────────────────────────────────────────────────────
  const statCards = [
    { label: 'Intercepted',    value: stats.total,                    unit: 'total packets',       color: 'text-ds-t1'   },
    { label: 'Blocked',        value: stats.blocked,                  unit: stats.pct(stats.blocked) + ' of traffic',   color: 'text-ds-red'   },
    { label: 'Alerts',         value: stats.alerted,                  unit: stats.pct(stats.alerted) + ' of traffic',  color: 'text-ds-amber' },
    { label: 'Threat Score',   value: stats.score.toFixed(3),         unit: 'Isolation Forest ML', color: stats.score > 0.45 ? 'text-ds-red' : stats.score > 0.15 ? 'text-ds-amber' : 'text-ds-green' },
    { label: 'Pkt / s',        value: pktRate.toFixed(1),             unit: '5 s rolling window',  color: pktRate > 18 ? 'text-ds-red' : 'text-ds-cyan' },
    { label: 'Events / min',   value: evtPerMin,                      unit: '60 s window',         color: 'text-ds-t2'  },
  ]

  return (
    <div className={`h-screen flex flex-col bg-ds-bg ${flashing ? 'flash-attack' : ''}`}>

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <header className="flex items-center justify-between px-5 py-2 bg-ds-panel border-b border-ds-border shrink-0">

        {/* Left: brand + threat level + session */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <div className={`w-2 h-2 rounded-full shrink-0 ${
              !connected ? 'bg-ds-t3'
              : threatLevel === 'SECURE' || threatLevel === 'GUARDED'
                ? 'bg-ds-green animate-pulse-fast'
                : 'bg-ds-red animate-pulse-fast'
            }`} />
            <span className="text-sm font-semibold text-ds-t1 font-mono tracking-wide">DroneShield</span>
            <span className="text-[11px] text-ds-t3 font-mono">IDS v1.0</span>
          </div>

          <div className="w-px h-4 bg-ds-border" />

          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-ds-t3 uppercase tracking-widest">Threat</span>
            <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold font-mono tracking-widest
                             ${connected ? `${THREAT_COLOR[threatLevel]} ${THREAT_BADGE[threatLevel]}` : 'text-ds-t3 border-ds-border'}`}>
              {connected ? threatLevel : 'OFFLINE'}
            </span>
          </div>

          <div className="w-px h-4 bg-ds-border" />
          <span className="text-[10px] font-mono text-ds-t3">
            Session <span className="text-ds-t2">{fmtDuration(sessionSecs)}</span>
          </span>
        </div>

        {/* Right: drone telemetry */}
        <div className="flex items-center gap-5 text-[11px] font-mono">
          <span className="text-ds-t3">
            ARM{' '}
            <span className={droneState.armed ? 'text-ds-red font-bold' : 'text-ds-t2'}>
              {droneState.armed ? 'ARMED' : 'SAFE'}
            </span>
          </span>
          <span className="text-ds-t3">
            MODE <span className="text-ds-cyan">{MODE_NAMES[droneState.mode] ?? droneState.mode}</span>
          </span>
          <span className="text-ds-t3">
            ALT <span className="text-ds-t1">{droneState.alt.toFixed(1)} m</span>
          </span>
          <span className="text-ds-t3">
            {droneState.lat.toFixed(5)}, {droneState.lon.toFixed(5)}
          </span>
          <div className="w-px h-4 bg-ds-border" />
          <span className={`font-semibold ${connected ? 'text-ds-green' : 'text-ds-red'}`}>
            {connected ? 'WS LIVE' : 'RECONNECTING'}
          </span>
        </div>
      </header>

      {/* ── Stat Cards ────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-6 gap-px bg-ds-border border-b border-ds-border shrink-0">
        {statCards.map(c => (
          <div key={c.label} className="bg-ds-panel px-4 py-2">
            <div className="text-[9px] text-ds-t3 uppercase tracking-widest mb-1">{c.label}</div>
            <div className={`text-[20px] font-bold font-mono leading-none ${c.color}`}>{c.value}</div>
            <div className="text-[9px] text-ds-t3 mt-1">{c.unit}</div>
          </div>
        ))}
      </div>

      {/* ── Main Content ──────────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden gap-px bg-ds-border">

        {/* ── Left: Event Stream ── */}
        <div className="w-[44%] bg-ds-panel flex flex-col overflow-hidden">
          <div className="px-4 py-1.5 shrink-0 border-b border-ds-border flex items-center justify-between bg-ds-panel">
            <span className="text-[9px] font-semibold text-ds-t3 uppercase tracking-widest">
              Event Stream
            </span>
            <div className="flex items-center gap-2 text-[10px] font-mono text-ds-t3">
              {selectedEvent && (
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-ds-blue hover:text-ds-t1 transition-colors text-[10px]"
                >
                  clear selection
                </button>
              )}
              <span>{events.length} / {MAX_EVENTS}</span>
            </div>
          </div>
          <PacketFeed
            events={events}
            selected={selectedEvent}
            onSelect={ev => setSelectedEvent(prev => prev === ev ? null : ev)}
          />
        </div>

        {/* ── Right: stacked panels ── */}
        <div className="flex-1 flex flex-col overflow-hidden gap-px bg-ds-border">

          {/* Threat Timeline */}
          <div className="bg-ds-panel overflow-hidden" style={{ flex: '0 0 38%' }}>
            <div className="px-4 py-1.5 border-b border-ds-border flex items-center justify-between bg-ds-panel shrink-0">
              <span className="text-[9px] font-semibold text-ds-t3 uppercase tracking-widest">
                Threat Score Timeline
              </span>
              <span className="text-[10px] font-mono text-ds-t3">60 s window · Isolation Forest</span>
            </div>
            <div style={{ height: 'calc(100% - 28px)' }}>
              <ThreatGraph scores={scores} />
            </div>
          </div>

          {/* Bottom row: map + tabbed panel */}
          <div className="flex flex-1 overflow-hidden gap-px bg-ds-border">

            {/* Drone Position */}
            <div className="w-[42%] bg-ds-panel flex flex-col overflow-hidden">
              <div className="px-4 py-1.5 shrink-0 border-b border-ds-border bg-ds-panel">
                <span className="text-[9px] font-semibold text-ds-t3 uppercase tracking-widest">
                  Drone Position
                </span>
              </div>
              <AttackMap events={events} droneState={droneState} />
            </div>

            {/* Tabbed panel: Intel / Protocol / Sources */}
            <div className="flex-1 bg-ds-panel flex flex-col overflow-hidden">

              {/* Tab bar */}
              <div className="flex items-stretch border-b border-ds-border bg-ds-panel shrink-0">
                {TABS.map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`px-4 py-1.5 text-[10px] font-medium border-r border-ds-border transition-colors select-none cursor-pointer
                               ${activeTab === tab.id
                                 ? 'text-ds-t1 bg-ds-panel2 border-b-2 border-b-ds-blue'
                                 : 'text-ds-t3 hover:text-ds-t2 hover:bg-ds-panel2/50'}`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              <div className="flex-1 overflow-hidden flex flex-col">
                {activeTab === 'intel'    && <ThreatIntel   events={events} />}
                {activeTab === 'protocol' && <ProtocolChart events={events} />}
                {activeTab === 'sources'  && <SourceTracker events={events} />}
              </div>

            </div>
          </div>
        </div>
      </div>

      {/* ── Command Bar ───────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 px-5 py-2 border-t border-ds-border bg-ds-panel shrink-0">

        {/* Sim label */}
        <span className="text-[9px] text-ds-t3 uppercase tracking-widest shrink-0 mr-1 font-mono">
          Sim
        </span>

        {/* Sim buttons */}
        {SIM_ACTIONS.map(btn => (
          <button
            key={btn.id}
            disabled={simLoading}
            onClick={() => startSim(btn.id)}
            className={simCls(btn.variant, simMode === btn.id, simLoading)}
          >
            {btn.label}
          </button>
        ))}

        {/* Active scenario */}
        <div className="flex items-center gap-1.5 text-[10px] font-mono ml-2">
          <span className="text-ds-t3">Active:</span>
          <span className={simMode === 'stopped' ? 'text-ds-t3' : 'text-ds-green font-semibold'}>
            {simMode === 'stopped' ? 'none' : simMode.replace('_', ' ').toUpperCase()}
          </span>
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Verdict counters */}
        <div className="flex gap-3 text-[10px] font-mono">
          <span className="text-ds-green">{events.filter(e => e.verdict === 'ALLOW').length} pass</span>
          <span className="text-ds-amber">{events.filter(e => e.verdict === 'ALERT').length} alert</span>
          <span className="text-ds-red">{events.filter(e => e.verdict === 'BLOCK').length} block</span>
        </div>

        <div className="w-px h-4 bg-ds-border mx-2" />

        {/* Export buttons */}
        <button
          onClick={exportJSON}
          disabled={events.length === 0}
          className="px-2.5 py-1 text-[10px] font-mono border border-ds-border/50 rounded
                     text-ds-t3 hover:text-ds-t1 hover:border-ds-borderhi transition-all
                     disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Export JSON
        </button>
        <button
          onClick={exportCSV}
          disabled={events.length === 0}
          className="px-2.5 py-1 text-[10px] font-mono border border-ds-border/50 rounded
                     text-ds-t3 hover:text-ds-t1 hover:border-ds-borderhi transition-all
                     disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Export CSV
        </button>
      </div>

      {/* ── Event Detail Drawer (modal) ───────────────────────────────────────── */}
      {selectedEvent && (
        <EventDrawer
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  )
}
