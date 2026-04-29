import { useMemo, useRef, useEffect, useState } from 'react'
import type { IDSEvent } from '../App'

interface Props {
  events:   IDSEvent[]
  onSelect: (ev: IDSEvent) => void
}

const WINDOW_SECS = 120
const SVG_W_PCT   = 100   // will fill container width
const SVG_H       = 80
const AXIS_H      = 20
const PLOT_H      = SVG_H - AXIS_H  // 60px for ticks
const TICK_H: Record<IDSEvent['verdict'], number> = {
  BLOCK: 24,
  ALERT: 16,
  ALLOW: 8,
}
const TICK_COLOR: Record<IDSEvent['verdict'], string> = {
  BLOCK: '#ef4444',
  ALERT: '#f59e0b',
  ALLOW: '#3d4f63',
}
const ATTACK_WINDOW_GAP_S = 2  // group BLOCK events within 2s

function timeToX(ts: number, nowMs: number, widthPx: number): number {
  const ageS = (nowMs - ts) / 1000
  // ageS=0 → rightmost, ageS=120 → leftmost
  return widthPx * (1 - ageS / WINDOW_SECS)
}

export default function AttackTimeline({ events, onSelect }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(600)

  useEffect(() => {
    const obs = new ResizeObserver(entries => {
      const w = entries[0]?.contentRect.width
      if (w && w > 0) setWidth(Math.floor(w))
    })
    if (containerRef.current) obs.observe(containerRef.current)
    return () => obs.disconnect()
  }, [])

  const nowMs = Date.now()

  // Filter to last WINDOW_SECS
  const visible = useMemo(() => {
    const cutoff = nowMs - WINDOW_SECS * 1000
    return events.filter(ev => new Date(ev.timestamp).getTime() >= cutoff)
  }, [events, nowMs])

  // Compute attack windows: groups of BLOCK events within 2s of each other
  const attackWindows = useMemo(() => {
    const blocks = visible
      .filter(ev => ev.verdict === 'BLOCK')
      .map(ev => new Date(ev.timestamp).getTime())
      .sort((a, b) => a - b)

    const windows: { startMs: number; endMs: number }[] = []
    for (const t of blocks) {
      const last = windows.at(-1)
      if (last && t - last.endMs <= ATTACK_WINDOW_GAP_S * 1000) {
        last.endMs = t
      } else {
        windows.push({ startMs: t, endMs: t })
      }
    }
    return windows
  }, [visible])

  const blockCount = visible.filter(e => e.verdict === 'BLOCK').length
  const alertCount = visible.filter(e => e.verdict === 'ALERT').length

  // Axis labels: -120, -90, -60, -30, 0
  const axisLabels = [-120, -90, -60, -30, 0]

  return (
    <div className="flex flex-col gap-0 w-full">
      {/* Summary */}
      <div className="flex items-center justify-between px-3 py-1 border-b border-ds-border shrink-0">
        <span className="text-[10px] font-mono text-ds-t2">
          <span className="text-ds-red font-bold">{blockCount}</span>
          <span className="text-ds-t3"> attacks · </span>
          <span className="text-ds-amber font-bold">{alertCount}</span>
          <span className="text-ds-t3"> alerts in last {WINDOW_SECS}s</span>
        </span>
        {/* Legend */}
        <div className="flex items-center gap-3 text-[9px] font-mono text-ds-t3">
          <span className="flex items-center gap-1">
            <span className="inline-block w-1 h-4 bg-ds-red rounded-sm" />BLOCK
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block w-1 h-3 bg-ds-amber rounded-sm" />ALERT
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block w-1 h-1.5 bg-ds-t3 rounded-sm" />ALLOW
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block w-3 h-3 rounded-sm bg-red-950/60 border border-ds-red/30" />
            Attack Window
          </span>
        </div>
      </div>

      {/* SVG timeline */}
      <div ref={containerRef} className="w-full overflow-hidden">
        <svg
          width="100%"
          height={SVG_H}
          style={{ display: 'block' }}
          viewBox={`0 0 ${width} ${SVG_H}`}
          preserveAspectRatio="none"
        >
          {/* Background */}
          <rect x={0} y={0} width={width} height={PLOT_H} fill="#0b0f1a" />

          {/* Attack windows */}
          {attackWindows.map((w, i) => {
            const x1 = timeToX(w.startMs, nowMs, width) - 4
            const x2 = timeToX(w.endMs,   nowMs, width) + 4
            const ww = Math.max(8, x2 - x1)
            return (
              <rect
                key={i}
                x={x1} y={0}
                width={ww} height={PLOT_H}
                fill="#ef444420"
                stroke="#ef444440"
                strokeWidth={0.5}
              />
            )
          })}

          {/* Grid lines at axis positions */}
          {axisLabels.map(s => {
            const x = width * (1 - Math.abs(s) / WINDOW_SECS)
            return (
              <line
                key={s}
                x1={x} y1={0} x2={x} y2={PLOT_H}
                stroke="#1e2a3a" strokeWidth={0.5}
              />
            )
          })}

          {/* Event ticks */}
          {visible.map((ev, i) => {
            const ts = new Date(ev.timestamp).getTime()
            const x  = timeToX(ts, nowMs, width)
            const h  = TICK_H[ev.verdict]
            const y  = PLOT_H - h
            return (
              <rect
                key={i}
                x={x - 1} y={y}
                width={2} height={h}
                fill={TICK_COLOR[ev.verdict]}
                opacity={ev.verdict === 'ALLOW' ? 0.4 : 0.85}
                style={{ cursor: 'pointer' }}
                onClick={() => onSelect(ev)}
              />
            )
          })}

          {/* Axis bar */}
          <rect x={0} y={PLOT_H} width={width} height={AXIS_H} fill="#0f1623" />
          <line x1={0} y1={PLOT_H} x2={width} y2={PLOT_H} stroke="#1e2a3a" strokeWidth={1} />

          {/* Axis labels */}
          {axisLabels.map(s => {
            const x = width * (1 - Math.abs(s) / WINDOW_SECS)
            return (
              <text
                key={s}
                x={x} y={PLOT_H + 13}
                textAnchor="middle"
                fontSize={8}
                fontFamily="monospace"
                fill="#3d4f63"
              >
                {s === 0 ? '0s' : `${s}s`}
              </text>
            )
          })}
        </svg>
      </div>
    </div>
  )
}
