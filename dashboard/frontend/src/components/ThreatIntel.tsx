import { useMemo } from 'react'
import type { IDSEvent } from '../App'
import { RULE_INTEL } from '../data/ruleIntel'

const SEV: Record<string, { text: string; bg: string; border: string; dot: string }> = {
  CRITICAL: { text: 'text-ds-red',   bg: 'bg-red-950/40',   border: 'border-ds-red/35',   dot: 'bg-ds-red'   },
  HIGH:     { text: 'text-ds-amber', bg: 'bg-amber-950/40', border: 'border-ds-amber/35', dot: 'bg-ds-amber' },
  MEDIUM:   { text: 'text-ds-blue',  bg: 'bg-blue-950/40',  border: 'border-ds-blue/35',  dot: 'bg-ds-blue'  },
  LOW:      { text: 'text-ds-t2',    bg: 'bg-ds-panel2',    border: 'border-ds-border',   dot: 'bg-ds-t3'    },
}

interface Props { events: IDSEvent[] }

export default function ThreatIntel({ events }: Props) {
  const activeThreats = useMemo(() => {
    const seen = new Set<string>()
    return events.filter(e =>
      e.verdict !== 'ALLOW' && e.rule &&
      !seen.has(e.rule) && (seen.add(e.rule), true),
    ).slice(0, 5)
  }, [events])

  const latest = events.find(e => e.verdict !== 'ALLOW' && e.rule)

  if (!latest) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-2 p-4">
        <div className="w-2 h-2 rounded-full bg-ds-green animate-pulse-fast" />
        <div className="text-ds-t2 text-xs font-medium">No Active Threats</div>
        <div className="text-ds-t3 text-[11px] text-center leading-relaxed">
          All intercepted MAVLink traffic is nominal.<br />
          IDS rule engine and Isolation Forest are monitoring.
        </div>
      </div>
    )
  }

  const intel = RULE_INTEL[latest.rule]
  const sev   = SEV[intel?.severity ?? 'LOW']

  return (
    <div className="flex-1 flex flex-col overflow-y-auto p-3 gap-3 text-[11px]">

      {/* Primary threat card */}
      {intel && (
        <div className={`rounded border ${sev.border} ${sev.bg} p-3 flex flex-col gap-2.5`}>
          <div className="flex items-start justify-between gap-2">
            <div>
              <div className={`text-xs font-semibold ${sev.text}`}>{intel.title}</div>
              <div className="text-ds-t3 text-[10px] mt-0.5">{intel.category}</div>
            </div>
            <div className="flex flex-col items-end gap-1 shrink-0">
              <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5 rounded border
                               ${sev.text} ${sev.border} ${sev.bg}`}>
                {intel.severity}
              </span>
              <span className="text-[10px] font-mono text-ds-t3">CVSSv3 {intel.cvss}</span>
            </div>
          </div>

          <p className="text-ds-t2 leading-relaxed">{intel.impact}</p>

          <div className="border-t border-ds-border/40 pt-2.5 flex flex-col gap-2">
            <div>
              <div className="text-[9px] text-ds-t3 uppercase tracking-widest mb-0.5">IDS Response</div>
              <div className="text-ds-cyan text-[11px]">{intel.recommendation}</div>
            </div>
            <div>
              <div className="text-[9px] text-ds-t3 uppercase tracking-widest mb-0.5">MITRE ATT&amp;CK for ICS</div>
              <div className="text-ds-purple text-[11px] font-mono">{intel.mitre}</div>
            </div>
          </div>
        </div>
      )}

      {/* Active rule list */}
      {activeThreats.length > 0 && (
        <div>
          <div className="text-[9px] text-ds-t3 uppercase tracking-widest mb-1.5">
            Distinct Rules Triggered
          </div>
          <div className="flex flex-col gap-px">
            {activeThreats.map((ev, i) => {
              const info   = RULE_INTEL[ev.rule]
              const rowSev = SEV[info?.severity ?? 'LOW']
              return (
                <div key={i} className="flex items-center gap-2 py-1.5 border-b border-ds-border/25">
                  <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${rowSev.dot}`} />
                  <span className={`font-mono text-[10px] w-[148px] shrink-0 ${rowSev.text}`}>
                    {ev.rule}
                  </span>
                  <span className="text-ds-t3 text-[10px] truncate flex-1">
                    {info?.category ?? 'Protocol Anomaly'}
                  </span>
                  <span className="font-mono text-[10px] text-ds-t3 shrink-0">
                    {ev.threat_score.toFixed(3)}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
