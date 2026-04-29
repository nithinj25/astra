import { useMemo } from 'react'
import type { IDSEvent } from '../App'

interface Props { events: IDSEvent[] }

interface Row {
  src:      string
  total:    number
  blocked:  number
  alerted:  number
  allowed:  number
  riskPct:  number
  lastSeen: string
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toISOString().substring(11, 19) }
  catch { return '—' }
}

export default function SourceTracker({ events }: Props) {
  const rows = useMemo((): Row[] => {
    const map: Record<string, { total: number; blocked: number; alerted: number; allowed: number; lastSeen: string }> = {}
    for (const ev of events) {
      const k = ev.source
      if (!map[k]) map[k] = { total: 0, blocked: 0, alerted: 0, allowed: 0, lastSeen: ev.timestamp }
      map[k].total++
      if (ev.verdict === 'BLOCK') map[k].blocked++
      else if (ev.verdict === 'ALERT') map[k].alerted++
      else map[k].allowed++
    }
    return Object.entries(map)
      .map(([src, v]) => ({
        src,
        ...v,
        riskPct: Math.round(((v.blocked + v.alerted) / Math.max(v.total, 1)) * 100),
      }))
      .sort((a, b) => b.blocked - a.blocked || b.riskPct - a.riskPct)
  }, [events])

  if (!rows.length) {
    return (
      <div className="flex-1 flex items-center justify-center text-ds-t3 text-xs">
        Awaiting traffic…
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col overflow-hidden text-[11px] font-mono">

      {/* Column header */}
      <div
        className="grid shrink-0 px-3 py-1.5 bg-ds-panel2 border-b border-ds-border
                   text-[9px] text-ds-t3 uppercase tracking-widest select-none"
        style={{ gridTemplateColumns: '1fr 44px 44px 44px 48px 70px' }}
      >
        <span>Source IP : Port</span>
        <span className="text-right">Total</span>
        <span className="text-right">Block</span>
        <span className="text-right">Alert</span>
        <span className="text-right">Risk</span>
        <span className="text-right">Last Seen</span>
      </div>

      {/* Rows */}
      <div className="flex-1 overflow-y-auto">
        {rows.map((row, i) => {
          const isMalicious = row.blocked > 0 || row.riskPct > 30
          return (
            <div
              key={i}
              title={`${row.src} — ${row.total} packets, risk ${row.riskPct}%`}
              className={`grid px-3 py-1.5 border-b border-ds-border/20 items-center
                         ${isMalicious ? 'bg-red-950/10' : ''}
                         hover:bg-ds-panel2/50 transition-colors`}
              style={{ gridTemplateColumns: '1fr 44px 44px 44px 48px 70px' }}
            >
              {/* Source */}
              <div className="flex items-center gap-1.5 min-w-0">
                <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                  row.blocked > 0      ? 'bg-ds-red'
                  : row.alerted > 0   ? 'bg-ds-amber'
                  :                     'bg-ds-green'
                }`} />
                <span className={`truncate ${isMalicious ? 'text-ds-red' : 'text-ds-t2'}`}>
                  {row.src}
                </span>
              </div>

              <span className="text-right text-ds-t3">{row.total}</span>

              <span className={`text-right font-semibold ${
                row.blocked > 0 ? 'text-ds-red' : 'text-ds-t3'
              }`}>
                {row.blocked}
              </span>

              <span className={`text-right ${
                row.alerted > 0 ? 'text-ds-amber' : 'text-ds-t3'
              }`}>
                {row.alerted}
              </span>

              {/* Risk % bar */}
              <div className="text-right relative">
                <span className={`text-[10px] font-semibold ${
                  row.riskPct > 50 ? 'text-ds-red'
                  : row.riskPct > 15 ? 'text-ds-amber'
                  : 'text-ds-t3'
                }`}>
                  {row.riskPct}%
                </span>
              </div>

              <span className="text-right text-ds-t3 text-[10px]">{fmtTime(row.lastSeen)}</span>
            </div>
          )
        })}
      </div>

      {/* Footer summary */}
      <div className="shrink-0 px-3 py-1.5 border-t border-ds-border text-[9px] text-ds-t3 flex gap-4">
        <span>{rows.length} unique sources</span>
        <span className="text-ds-red">{rows.filter(r => r.blocked > 0).length} adversarial</span>
        <span className="text-ds-green">{rows.filter(r => r.blocked === 0 && r.alerted === 0).length} trusted</span>
      </div>
    </div>
  )
}
