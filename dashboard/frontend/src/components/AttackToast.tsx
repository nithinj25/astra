import { useEffect, useRef, useState } from 'react'
import type { IDSEvent } from '../App'
import { RULE_INTEL } from '../data/ruleIntel'

interface Props { events: IDSEvent[] }

interface ToastItem { id: string; ev: IDSEvent; born: number }

const LIFESPAN = 6500 // ms visible

export default function AttackToast({ events }: Props) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const seen = useRef(new Set<string>())

  useEffect(() => {
    if (!events.length) return
    const ev = events[0]
    if (ev.verdict === 'ALLOW' || !ev.rule) return
    const id = `${ev.timestamp}_${ev.rule}_${ev.source}`
    if (seen.current.has(id)) return
    seen.current.add(id)
    const born = Date.now()
    setToasts(prev => [{ id, ev, born }, ...prev].slice(0, 3))
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), LIFESPAN + 500)
  }, [events])

  if (!toasts.length) return null

  return (
    <div
      style={{
        position: 'fixed', top: 56, right: 12, zIndex: 100,
        display: 'flex', flexDirection: 'column', gap: 8,
        width: 390, pointerEvents: 'none',
      }}
    >
      {toasts.map(t => <ToastCard key={t.id} toast={t} />)}
    </div>
  )
}

function ToastCard({ toast }: { toast: ToastItem }) {
  const { ev } = toast
  const info = RULE_INTEL[ev.rule]
  const block = ev.verdict === 'BLOCK'

  const [fading, setFading] = useState(false)
  useEffect(() => {
    const t = setTimeout(() => setFading(true), LIFESPAN - 500)
    return () => clearTimeout(t)
  }, [])

  const accent = block ? '#ef4444' : '#f59e0b'
  const bg     = block ? '#150303' : '#130e00'
  const border = block ? 'rgba(239,68,68,0.40)' : 'rgba(245,158,11,0.40)'
  const title  = block ? '#fca5a5' : '#fde68a'

  // Impact text: prefer blocked_impact (short, action-oriented), fall back to first sentence of info.impact
  const impactText = ev.blocked_impact
    || (info?.impact ? info.impact.split('.')[0] + '.' : '')

  return (
    <div
      style={{
        background: bg,
        border: `1px solid ${border}`,
        borderLeft: `3px solid ${accent}`,
        borderRadius: 7,
        padding: '11px 14px 9px',
        boxShadow: `0 0 28px ${accent}1a, 0 6px 20px rgba(0,0,0,0.65)`,
        opacity: fading ? 0 : 1,
        transform: fading ? 'translateX(14px)' : 'translateX(0)',
        transition: 'opacity 0.45s ease, transform 0.45s ease',
        animation: 'toast-slide-in 0.32s ease-out',
      }}
    >
      {/* Row 1: verdict badge + rule title + CVSS */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
        <span style={{
          background: accent, color: '#fff',
          fontSize: 9, fontWeight: 800, fontFamily: 'monospace',
          padding: '2px 7px', borderRadius: 3, letterSpacing: '0.12em',
          flexShrink: 0,
        }}>
          {ev.verdict}
        </span>
        <span style={{
          color: title, fontSize: 11, fontWeight: 700,
          fontFamily: 'monospace', flex: 1, lineHeight: 1.3,
        }}>
          {info?.title ?? ev.rule}
        </span>
        {info && (
          <span style={{ color: '#6b7280', fontSize: 9, fontFamily: 'monospace', flexShrink: 0 }}>
            CVSS {info.cvss}
          </span>
        )}
      </div>

      {/* Row 2: category + severity */}
      {info && (
        <div style={{
          color: accent, fontSize: 9, fontFamily: 'monospace',
          marginBottom: 6, opacity: 0.85, letterSpacing: '0.05em',
        }}>
          {info.category.toUpperCase()}  ·  {info.severity}
        </div>
      )}

      {/* Row 3: impact description */}
      {impactText && (
        <p style={{
          color: '#9ca3af', fontSize: 10.5, lineHeight: 1.5,
          margin: '0 0 6px', fontFamily: 'system-ui, sans-serif',
        }}>
          {impactText}
        </p>
      )}

      {/* Row 4: MITRE reference */}
      {info?.mitre && (
        <div style={{
          color: '#4b5563', fontSize: 9, fontFamily: 'monospace',
          marginBottom: 8, letterSpacing: '0.03em',
        }}>
          {info.mitre}
        </div>
      )}

      {/* Progress bar */}
      <div style={{ height: 2, background: '#1f2937', borderRadius: 1, overflow: 'hidden' }}>
        <div style={{
          height: '100%', background: accent,
          width: '100%', transformOrigin: 'left',
          animation: `shrink-bar ${LIFESPAN}ms linear forwards`,
        }} />
      </div>
    </div>
  )
}
