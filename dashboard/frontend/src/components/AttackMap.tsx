import { useEffect, useState } from 'react'
import type { IDSEvent } from '../App'

interface Props {
  events:     IDSEvent[]
  droneState: IDSEvent['drone_state']
}

interface TrailPoint { lat: number; lon: number; verdict: IDSEvent['verdict'] }

const ORIGIN_LAT = 37.7749
const ORIGIN_LON = -122.4194
const MAX_TRAIL  = 60
const W          = 280
const H          = 230
const SCALE      = 6000

// Geofence radius 300m → degrees: 300/111000 * SCALE ≈ 16px
const GEOFENCE_PX = (300 / 111000) * SCALE

function project(lat: number, lon: number): [number, number] {
  return [
    (lon - ORIGIN_LON) * SCALE + W / 2,
    (ORIGIN_LAT - lat) * SCALE + H / 2,
  ]
}

function clamp(v: number, lo: number, hi: number) {
  return Math.min(hi, Math.max(lo, v))
}

export default function AttackMap({ events, droneState }: Props) {
  const [trail, setTrail]       = useState<TrailPoint[]>([])
  const [pulseTick, setPulseTick] = useState(0)

  useEffect(() => {
    if (!events.length) return
    const ev = events[0]
    if (ev.drone_state.lat === 0 && ev.drone_state.lon === 0) return
    setTrail(prev => [
      { lat: ev.drone_state.lat, lon: ev.drone_state.lon, verdict: ev.verdict },
      ...prev,
    ].slice(0, MAX_TRAIL))
  }, [events])

  // Pulse animation tick for geofence breach
  useEffect(() => {
    if (!droneState.geofence_breach) return
    const iv = setInterval(() => setPulseTick(t => t + 1), 600)
    return () => clearInterval(iv)
  }, [droneState.geofence_breach])

  const [px, py]  = project(droneState.lat, droneState.lon)
  const dx        = clamp(px, 10, W - 10)
  const dy        = clamp(py, 10, H - 10)

  // Heading indicator
  const headingRad = ((droneState.heading ?? 0) - 90) * Math.PI / 180
  const lineLen    = 15
  const hx2        = dx + lineLen * Math.cos(headingRad)
  const hy2        = dy + lineLen * Math.sin(headingRad)

  const gridX = Array.from({ length: 7 }, (_, i) => Math.round(i * W / 6))
  const gridY = Array.from({ length: 6 }, (_, i) => Math.round(i * H / 5))

  const legitTrail = trail.filter(p => p.verdict !== 'BLOCK')
  const spoofPts   = trail.filter(p =>
    p.verdict === 'BLOCK' &&
    events.some(e => e.packet_type === 'GPS_INPUT' &&
                     e.drone_state.lat === p.lat && e.drone_state.lon === p.lon),
  )

  // Home position
  const [homeX, homeY] = project(ORIGIN_LAT, ORIGIN_LON)

  const breach = droneState.geofence_breach ?? false
  const fencePulse = breach && pulseTick % 2 === 0

  return (
    <div className="flex-1 flex flex-col items-center justify-center px-3 py-2 gap-2">
      <svg
        width={W} height={H}
        className="rounded border border-ds-border"
        style={{ background: 'radial-gradient(ellipse at 50% 55%, #0e1729 0%, #0b0f1a 100%)' }}
      >
        {/* Grid */}
        {gridX.map(v => <line key={`gx${v}`} x1={v} y1={0} x2={v} y2={H} stroke="#1e2a3a" strokeWidth={0.5} />)}
        {gridY.map(v => <line key={`gy${v}`} x1={0} y1={v} x2={W} y2={v} stroke="#1e2a3a" strokeWidth={0.5} />)}

        {/* Geofence circle */}
        <circle
          cx={homeX} cy={homeY}
          r={GEOFENCE_PX}
          fill="none"
          stroke={breach ? '#ef4444' : '#22c55e'}
          strokeWidth={breach ? (fencePulse ? 1.5 : 0.8) : 0.8}
          strokeDasharray="4 3"
          opacity={breach ? (fencePulse ? 0.9 : 0.5) : 0.35}
        />

        {/* Home position crosshair (ds-cyan) */}
        <line x1={homeX - 6} y1={homeY} x2={homeX + 6} y2={homeY} stroke="#06b6d4" strokeWidth={1.2} />
        <line x1={homeX} y1={homeY - 6} x2={homeX} y2={homeY + 6} stroke="#06b6d4" strokeWidth={1.2} />
        <circle cx={homeX} cy={homeY} r={2} fill="#06b6d4" opacity={0.7} />

        {/* Legitimate flight path */}
        {legitTrail.length > 1 && (
          <polyline
            points={legitTrail.map(p => {
              const [x, y] = project(p.lat, p.lon)
              return `${clamp(x, 0, W)},${clamp(y, 0, H)}`
            }).join(' ')}
            fill="none" stroke="#22c55e" strokeWidth={1} strokeOpacity={0.35}
          />
        )}

        {/* GPS spoof injection points */}
        {spoofPts.map((p, i) => {
          const [x, y] = project(p.lat, p.lon)
          const cx = clamp(x, 4, W - 4)
          const cy = clamp(y, 4, H - 4)
          return (
            <g key={i}>
              <circle cx={cx} cy={cy} r={3}  fill="#ef4444" opacity={0.75} />
              <circle cx={cx} cy={cy} r={7}  fill="none" stroke="#ef4444" strokeWidth={0.5} opacity={0.3} />
            </g>
          )
        })}

        {/* Heading indicator (cyan line from drone position) */}
        <line
          x1={dx} y1={dy}
          x2={clamp(hx2, 2, W - 2)} y2={clamp(hy2, 2, H - 2)}
          stroke="#06b6d4"
          strokeWidth={1.5}
          strokeOpacity={0.85}
          strokeLinecap="round"
        />

        {/* Drone icon */}
        <g>
          <polygon
            points={`${dx},${dy - 9} ${dx - 7},${dy + 6} ${dx + 7},${dy + 6}`}
            fill="#22c55e" stroke="#22c55e" strokeWidth={1} opacity={0.92}
          />
          <circle cx={dx} cy={dy} r={20} fill="none" stroke="#22c55e"
                  strokeWidth={0.5} strokeOpacity={0.18} strokeDasharray="3 3" />
        </g>

        {/* Legend */}
        <g transform="translate(6,6)" fontSize={8} fontFamily="monospace">
          <rect x={0} y={0} width={88} height={42} fill="#0b0f1a" opacity={0.88} rx={2} />
          <line x1={4} y1={9} x2={13} y2={9} stroke="#22c55e" strokeWidth={1.5} />
          <text x={17} y={12} fill="#7f8ea3">Flight track</text>
          <circle cx={8} cy={22} r={3} fill="#ef4444" opacity={0.75} />
          <text x={17} y={25} fill="#7f8ea3">GPS spoof</text>
          <line x1={4} y1={33} x2={13} y2={33} stroke="#06b6d4" strokeWidth={1.5} />
          <text x={17} y={36} fill="#7f8ea3">Heading</text>
        </g>

        {/* Battery overlay — bottom left */}
        <g transform={`translate(6,${H - 16})`} fontSize={8} fontFamily="monospace">
          <rect x={0} y={0} width={110} height={12} fill="#0b0f1a" opacity={0.8} rx={1.5} />
          <text x={4} y={9} fill="#7f8ea3">
            {`BATT: ${(droneState.battery_pct ?? 100).toFixed(0)}% | SPD: ${(droneState.groundspeed ?? 0).toFixed(1)} m/s`}
          </text>
        </g>
      </svg>

      {/* Coordinate footer */}
      <div className="flex gap-4 text-[10px] font-mono text-ds-t3">
        <span>{droneState.lat.toFixed(5)} N</span>
        <span>{Math.abs(droneState.lon).toFixed(5)} W</span>
        <span>{droneState.alt.toFixed(1)} m AGL</span>
      </div>
    </div>
  )
}
