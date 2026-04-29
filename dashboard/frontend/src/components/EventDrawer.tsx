import { useEffect } from 'react'
import type { IDSEvent } from '../App'
import { RULE_INTEL } from '../data/ruleIntel'

const MODE_NAMES: Record<number, string> = {
  0: 'STABILIZE', 3: 'AUTO', 4: 'GUIDED', 6: 'RTL', 9: 'LAND',
}

const SEV_CLS: Record<string, { text: string; border: string; bg: string }> = {
  CRITICAL: { text: 'text-ds-red',   border: 'border-ds-red/40',   bg: 'bg-red-950/40'   },
  HIGH:     { text: 'text-ds-amber', border: 'border-ds-amber/40', bg: 'bg-amber-950/40' },
  MEDIUM:   { text: 'text-ds-blue',  border: 'border-ds-blue/40',  bg: 'bg-blue-950/40'  },
  LOW:      { text: 'text-ds-t2',    border: 'border-ds-border',   bg: 'bg-ds-panel2'    },
}

interface Props {
  event:   IDSEvent
  onClose: () => void
}

function Field({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="flex items-baseline gap-2 py-[3px] border-b border-ds-border/20">
      <span className="text-ds-t3 text-[10px] w-28 shrink-0 font-mono">{label}</span>
      <span className={`font-mono text-[11px] ${accent ?? 'text-ds-t1'}`}>{value}</span>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <div className="text-[9px] text-ds-t3 uppercase tracking-widest mb-1 border-b border-ds-border pb-1">
        {title}
      </div>
      {children}
    </div>
  )
}

export default function EventDrawer({ event, onClose }: Props) {
  const intel   = RULE_INTEL[event.rule]
  const sevCls  = SEV_CLS[intel?.severity ?? 'LOW']

  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  const verdictCls =
    event.verdict === 'BLOCK' ? { text: 'text-ds-red',   border: 'border-ds-red/40',   bg: 'bg-red-950/40'   } :
    event.verdict === 'ALERT' ? { text: 'text-ds-amber', border: 'border-ds-amber/40', bg: 'bg-amber-950/40' } :
                                { text: 'text-ds-green', border: 'border-ds-green/40', bg: 'bg-green-950/40' }

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/55 z-40 backdrop-blur-[1px]"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-8">
        <div
          className="bg-ds-panel border border-ds-border rounded w-full max-w-3xl
                     max-h-[85vh] overflow-y-auto shadow-2xl flex flex-col"
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-5 py-3 border-b border-ds-border shrink-0">
            <div className="flex items-center gap-3">
              <div className={`w-2 h-2 rounded-full ${
                event.verdict === 'BLOCK' ? 'bg-ds-red animate-pulse-fast'
                : event.verdict === 'ALERT' ? 'bg-ds-amber'
                : 'bg-ds-green'
              }`} />
              <span className="font-mono text-sm font-semibold text-ds-t1">{event.packet_type}</span>
              <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border
                               ${verdictCls.text} ${verdictCls.border} ${verdictCls.bg}`}>
                {event.verdict}
              </span>
              {intel && (
                <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border
                                 ${sevCls.text} ${sevCls.border} ${sevCls.bg}`}>
                  {intel.severity}  ·  CVSSv3 {intel.cvss}
                </span>
              )}
            </div>
            <button
              onClick={onClose}
              className="text-ds-t3 hover:text-ds-t1 transition-colors text-xs font-mono px-2 py-1
                         border border-ds-border/40 rounded hover:border-ds-borderhi"
            >
              ESC / close
            </button>
          </div>

          {/* Body */}
          <div className="p-5 grid grid-cols-2 gap-6 text-[11px]">

            {/* ── Left column ── */}
            <div className="flex flex-col gap-5">

              <Section title="Event Details">
                <Field label="Timestamp"    value={new Date(event.timestamp).toISOString()} />
                <Field label="Source"       value={event.source} accent="text-ds-cyan" />
                <Field label="Protocol"     value={event.packet_type} accent="text-ds-cyan" />
                <Field label="Rule"         value={event.rule || '—'} accent={event.rule ? verdictCls.text : undefined} />
                <Field label="Attack Type"  value={event.attack_type ?? 'N/A'} />
                <Field label="Threat Score" value={event.threat_score.toFixed(4)}
                  accent={event.threat_score > 0.45 ? 'text-ds-red font-bold'
                         : event.threat_score > 0.15 ? 'text-ds-amber'
                         : 'text-ds-green'} />
              </Section>

              {intel && (
                <Section title="Threat Classification">
                  <Field label="Category"  value={intel.category} />
                  <Field label="Severity"  value={intel.severity}  accent={sevCls.text} />
                  <Field label="CVSSv3"    value={String(intel.cvss)} accent="text-ds-t1" />
                  <Field label="MITRE ATT&CK" value={intel.mitre}  accent="text-ds-purple" />
                </Section>
              )}

              {intel?.fields && (
                <Section title="Decoded MAVLink Fields">
                  {intel.fields.map(f => (
                    <Field key={f.label} label={f.label} value={f.desc} accent="text-ds-t2" />
                  ))}
                </Section>
              )}
            </div>

            {/* ── Right column ── */}
            <div className="flex flex-col gap-5">

              <Section title="Drone State at Event Time">
                <Field label="Armed"     value={event.drone_state.armed ? 'ARMED — PROPULSION ACTIVE' : 'SAFE — DISARMED'}
                  accent={event.drone_state.armed ? 'text-ds-red font-bold' : 'text-ds-green'} />
                <Field label="Mode"      value={`${MODE_NAMES[event.drone_state.mode] ?? event.drone_state.mode} (${event.drone_state.mode})`} />
                <Field label="Latitude"  value={`${event.drone_state.lat.toFixed(6)}°`} />
                <Field label="Longitude" value={`${event.drone_state.lon.toFixed(6)}°`} />
                <Field label="Altitude"  value={`${event.drone_state.alt.toFixed(1)} m AGL`} />
              </Section>

              {intel && (
                <Section title="Operational Impact">
                  <p className="text-ds-t2 leading-relaxed text-[11px] pt-1">{intel.impact}</p>
                </Section>
              )}

              {intel && (
                <Section title="Recommended Response">
                  <p className="text-ds-cyan leading-relaxed text-[11px] pt-1">{intel.recommendation}</p>
                </Section>
              )}

              {/* Raw source info */}
              <Section title="Network Context">
                <Field label="IDS Port"    value="14551 (proxy listener)" />
                <Field label="Drone Port"  value="14550 (autopilot)" />
                <Field label="GCS Source"  value={event.source} accent="text-ds-t2" />
                <Field label="IDS Action"  value={event.verdict === 'BLOCK' ? 'Packet dropped — not forwarded to autopilot'
                                                 : event.verdict === 'ALERT' ? 'Packet forwarded with alert raised'
                                                 : 'Packet forwarded — nominal traffic'}
                  accent={verdictCls.text} />
              </Section>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
