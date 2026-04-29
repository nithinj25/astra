import { useMemo, useState } from 'react'
import type { IDSEvent } from '../App'

interface Props {
  events:          IDSEvent[]
  acknowledgedIds: Set<string>
  onAcknowledge:   (ev: IDSEvent) => void
}

export function eventId(ev: IDSEvent): string {
  return `${ev.timestamp}_${ev.source}`
}

function fmtTime(ts: string): string {
  const d = new Date(ts)
  return [
    String(d.getHours()).padStart(2, '0'),
    String(d.getMinutes()).padStart(2, '0'),
    String(d.getSeconds()).padStart(2, '0'),
  ].join(':')
}

function SeverityDot({ verdict }: { verdict: IDSEvent['verdict'] }) {
  const cls =
    verdict === 'BLOCK' ? 'bg-ds-red'
    : verdict === 'ALERT' ? 'bg-ds-amber'
    : 'bg-ds-t3'
  return <span className={`w-2 h-2 rounded-full shrink-0 ${cls}`} />
}

export default function AlertQueue({ events, acknowledgedIds, onAcknowledge }: Props) {
  const [justAcked, setJustAcked] = useState<Set<string>>(new Set())

  // Only show BLOCK and ALERT
  const alertable = useMemo(
    () => events.filter(e => e.verdict === 'BLOCK' || e.verdict === 'ALERT'),
    [events],
  )

  const pending = useMemo(
    () => alertable.filter(e => !acknowledgedIds.has(eventId(e))).slice(0, 20),
    [alertable, acknowledgedIds],
  )

  const investigated = useMemo(
    () => alertable.filter(e => acknowledgedIds.has(eventId(e))).slice(0, 10),
    [alertable, acknowledgedIds],
  )

  function handleAck(ev: IDSEvent) {
    const id = eventId(ev)
    setJustAcked(prev => new Set([...prev, id]))
    onAcknowledge(ev)
  }

  const pendingCount      = pending.length
  const investigatedCount = investigated.length

  return (
    <div className="flex-1 flex flex-col overflow-hidden text-[11px]">

      {/* Metrics row */}
      <div className="flex items-center gap-4 px-3 py-1.5 border-b border-ds-border shrink-0 bg-ds-panel">
        <span className="font-mono">
          <span className="text-ds-t3">Pending: </span>
          <span className={pendingCount > 0 ? 'text-ds-red font-bold' : 'text-ds-t2'}>
            {pendingCount}
          </span>
        </span>
        <span className="font-mono">
          <span className="text-ds-t3">Investigated: </span>
          <span className={investigatedCount > 0 ? 'text-ds-green font-semibold' : 'text-ds-t2'}>
            {investigatedCount}
          </span>
        </span>
        <span className="font-mono text-ds-t3">
          Response time: <span className="text-ds-t2">—</span>
        </span>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">

        {alertable.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2 p-6">
            <div className="w-2 h-2 rounded-full bg-ds-green animate-pulse-fast" />
            <div className="text-ds-t2 text-xs font-medium">Alert Queue Empty</div>
            <div className="text-ds-t3 text-[10px] text-center leading-relaxed">
              No BLOCK or ALERT events yet.<br />All intercepted traffic is nominal.
            </div>
          </div>
        ) : (
          <>
            {/* Pending section */}
            {pending.length > 0 && (
              <div>
                <div className="px-3 py-1 text-[9px] text-ds-t3 uppercase tracking-widest bg-ds-panel2 border-b border-ds-border sticky top-0">
                  Pending ({pending.length})
                </div>
                {pending.map(ev => {
                  const id    = eventId(ev)
                  const acked = justAcked.has(id)
                  return (
                    <div
                      key={id}
                      className="flex items-center gap-2 px-3 py-2 border-b border-ds-border/40
                                 hover:bg-ds-panel2/50 transition-colors"
                    >
                      <SeverityDot verdict={ev.verdict} />

                      <span className={`font-mono text-[10px] w-[132px] shrink-0 truncate ${
                        ev.verdict === 'BLOCK' ? 'text-ds-red' : 'text-ds-amber'
                      }`}>
                        {ev.rule || ev.attack_type || 'UNKNOWN'}
                      </span>

                      <span className="font-mono text-[10px] text-ds-cyan w-[110px] shrink-0 truncate">
                        {ev.source}
                      </span>

                      <span className="font-mono text-[10px] text-ds-t3 shrink-0">
                        {fmtTime(ev.timestamp)}
                      </span>

                      <span className={`font-mono text-[10px] shrink-0 w-12 text-right ${
                        ev.threat_score > 0.45 ? 'text-ds-red' :
                        ev.threat_score > 0.15 ? 'text-ds-amber' : 'text-ds-t2'
                      }`}>
                        {ev.threat_score.toFixed(3)}
                      </span>

                      <div className="flex-1" />

                      <button
                        onClick={() => handleAck(ev)}
                        disabled={acked}
                        className={`px-2 py-0.5 text-[9px] font-mono border rounded transition-all shrink-0
                          ${acked
                            ? 'border-ds-green/40 text-ds-green bg-green-950/30 cursor-default'
                            : 'border-ds-border/60 text-ds-t3 hover:text-ds-t1 hover:border-ds-borderhi cursor-pointer'
                          }`}
                      >
                        {acked ? '✓ Done' : 'Acknowledge'}
                      </button>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Investigated section */}
            {investigated.length > 0 && (
              <div>
                <div className="px-3 py-1 text-[9px] text-ds-t3 uppercase tracking-widest bg-ds-panel2 border-b border-ds-border sticky top-0">
                  Investigated ({investigated.length})
                </div>
                {investigated.map(ev => {
                  const id = eventId(ev)
                  return (
                    <div
                      key={id}
                      className="flex items-center gap-2 px-3 py-1.5 border-b border-ds-border/20 opacity-50"
                    >
                      <span className="w-2 h-2 rounded-full shrink-0 bg-ds-green" />
                      <span className="font-mono text-[10px] text-ds-t2 w-[132px] shrink-0 truncate">
                        {ev.rule || ev.attack_type || 'UNKNOWN'}
                      </span>
                      <span className="font-mono text-[10px] text-ds-t3 w-[110px] shrink-0 truncate">
                        {ev.source}
                      </span>
                      <span className="font-mono text-[10px] text-ds-t3 shrink-0">
                        {fmtTime(ev.timestamp)}
                      </span>
                      <span className="flex-1" />
                      <span className="text-[9px] font-mono text-ds-green">✓ Investigated</span>
                    </div>
                  )
                })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
