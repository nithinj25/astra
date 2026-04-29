import { useRef, useEffect, useState, useMemo } from 'react'
import type { IDSEvent } from '../App'

const VERDICT_CFG = {
  ALLOW: { dot: 'bg-ds-green', text: 'text-ds-green', row: '',              badge: 'PASS' },
  ALERT: { dot: 'bg-ds-amber', text: 'text-ds-amber', row: 'bg-amber-950/10', badge: 'ALRT' },
  BLOCK: { dot: 'bg-ds-red',   text: 'text-ds-red',   row: 'bg-red-950/10',  badge: 'BLCK' },
}

const RULE_TIP: Record<string, string> = {
  UNTRUSTED_ARM:          'Unauthorized COMMAND_ARM from unregistered GCS source',
  GPS_JUMP:               'GPS_INPUT position delta >50 m — coordinate injection',
  UNEXPECTED_MODE_CHANGE: 'SET_MODE from unregistered controller — state manipulation',
  RATE_LIMIT:             'Packet rate >20 pkt/s — MAVLink protocol flood',
}

type VerdictFilter = 'ALL' | 'BLOCK' | 'ALERT' | 'ALLOW'

function fmtTime(ts: string): string {
  try { return new Date(ts).toISOString().substring(11, 23) }
  catch { return ts.substring(0, 12) }
}

interface Props {
  events:    IDSEvent[]
  selected?: IDSEvent | null
  onSelect?: (ev: IDSEvent) => void
}

const FILTER_BTNS: { id: VerdictFilter; label: string; cls: string; active: string }[] = [
  { id: 'ALL',   label: 'All',   cls: 'text-ds-t3 border-ds-border',   active: 'bg-ds-panel2 text-ds-t1 border-ds-borderhi' },
  { id: 'BLOCK', label: 'Block', cls: 'text-ds-red/60 border-ds-red/20',   active: 'bg-red-950/30 text-ds-red border-ds-red/50' },
  { id: 'ALERT', label: 'Alert', cls: 'text-ds-amber/60 border-ds-amber/20', active: 'bg-amber-950/30 text-ds-amber border-ds-amber/50' },
  { id: 'ALLOW', label: 'Pass',  cls: 'text-ds-green/60 border-ds-green/20', active: 'bg-green-950/30 text-ds-green border-ds-green/50' },
]

export default function PacketFeed({ events, selected, onSelect }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>('ALL')
  const [search,        setSearch]        = useState('')

  // Auto-scroll to top on new events (only when at the top)
  useEffect(() => {
    if (ref.current && ref.current.scrollTop < 60) {
      ref.current.scrollTop = 0
    }
  }, [events.length])

  const filtered = useMemo(() => {
    let list = events
    if (verdictFilter !== 'ALL') list = list.filter(e => e.verdict === verdictFilter)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(e =>
        e.rule?.toLowerCase().includes(q) ||
        e.source.toLowerCase().includes(q) ||
        e.packet_type.toLowerCase().includes(q),
      )
    }
    return list
  }, [events, verdictFilter, search])

  return (
    <div className="flex flex-col h-full overflow-hidden font-mono text-[11px]">

      {/* ── Filter bar ── */}
      <div className="flex items-center gap-1.5 px-3 py-1.5 border-b border-ds-border bg-ds-panel2 shrink-0">
        {FILTER_BTNS.map(btn => (
          <button
            key={btn.id}
            onClick={() => setVerdictFilter(btn.id)}
            className={`px-2 py-0.5 text-[10px] border rounded transition-all select-none cursor-pointer
                        ${verdictFilter === btn.id ? btn.active : btn.cls + ' hover:opacity-80'}`}
          >
            {btn.label}
          </button>
        ))}
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search rule / source / type…"
          className="flex-1 ml-1 bg-transparent border-b border-ds-border/40 text-[10px] text-ds-t1
                     placeholder:text-ds-t3 outline-none py-0.5 focus:border-ds-borderhi transition-colors"
        />
        {search && (
          <button onClick={() => setSearch('')} className="text-ds-t3 hover:text-ds-t1 transition-colors text-[10px]">
            ×
          </button>
        )}
        <span className="text-ds-t3 text-[9px] ml-1 shrink-0">{filtered.length}</span>
      </div>

      {/* ── Column header ── */}
      <div
        className="grid shrink-0 px-3 py-1.5 bg-ds-panel2 border-b border-ds-border
                   text-[9px] font-medium text-ds-t3 uppercase tracking-widest select-none"
        style={{ gridTemplateColumns: '12px 92px 40px 106px 1fr 50px' }}
      >
        <span />
        <span>Time (UTC)</span>
        <span>Action</span>
        <span>Protocol</span>
        <span>Rule / Source</span>
        <span className="text-right">Score</span>
      </div>

      {/* ── Rows ── */}
      <div ref={ref} className="flex-1 overflow-y-auto">
        {filtered.length === 0 && (
          <div className="flex items-center justify-center h-20 text-ds-t3 text-xs">
            {events.length === 0 ? 'Awaiting MAVLink traffic…' : 'No events match filter.'}
          </div>
        )}

        {filtered.map((ev, i) => {
          const cfg        = VERDICT_CFG[ev.verdict] ?? VERDICT_CFG.ALLOW
          const tip        = ev.rule ? (RULE_TIP[ev.rule] ?? ev.rule) : ev.source
          const isSelected = selected === ev

          return (
            <div
              key={i}
              title={tip}
              onClick={() => onSelect?.(ev)}
              className={`grid items-center px-3 py-[4px] border-b border-ds-border/20
                         ${cfg.row} transition-colors cursor-pointer
                         ${isSelected
                           ? 'bg-ds-borderhi ring-1 ring-inset ring-ds-blue/40'
                           : 'hover:bg-ds-panel2/60'}`}
              style={{ gridTemplateColumns: '12px 92px 40px 106px 1fr 50px' }}
            >
              {/* Status dot */}
              <div><div className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} /></div>

              {/* Timestamp */}
              <span className="text-ds-t3">{fmtTime(ev.timestamp)}</span>

              {/* Verdict */}
              <span className={`text-[10px] font-semibold ${cfg.text}`}>{cfg.badge}</span>

              {/* Protocol */}
              <span className="text-ds-cyan truncate">{ev.packet_type}</span>

              {/* Rule or source */}
              <span className="truncate">
                {ev.rule
                  ? <span className={cfg.text}>{ev.rule}</span>
                  : <span className="text-ds-t3">{ev.source}</span>
                }
              </span>

              {/* Score */}
              <span className={`text-right ${
                ev.threat_score > 0.45 ? 'text-ds-red font-bold'
                : ev.threat_score > 0.15 ? 'text-ds-amber'
                : 'text-ds-t3'
              }`}>
                {ev.threat_score.toFixed(3)}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
