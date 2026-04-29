import type { IDSEvent } from '../App'

interface Props {
  droneState: IDSEvent['drone_state']
  connected:  boolean
}

const PHASE_COLOR: Record<string, string> = {
  PREFLIGHT: 'bg-ds-panel2 text-ds-t2 border-ds-border',
  ARMED:     'bg-amber-950/50 text-ds-amber border-ds-amber/40',
  TAKEOFF:   'bg-blue-950/50 text-ds-blue border-ds-blue/40',
  CRUISE:    'bg-green-950/50 text-ds-green border-ds-green/40',
  RTL:       'bg-amber-950/50 text-ds-amber border-ds-amber/40',
  LANDING:   'bg-blue-950/50 text-ds-blue border-ds-blue/40',
  LANDED:    'bg-ds-panel2 text-ds-t2 border-ds-border',
}

function batteryBar(pct: number): string {
  const filled = Math.round((pct / 100) * 8)
  return '▓'.repeat(filled) + '░'.repeat(8 - filled)
}

function batteryColor(pct: number): string {
  if (pct > 50) return 'text-ds-green'
  if (pct > 20) return 'text-ds-amber'
  return 'text-ds-red'
}

function gpsQuality(sats: number): string {
  if (sats > 8) return 'LOCK'
  if (sats >= 4) return 'WEAK'
  return 'NO FIX'
}

function gpsColor(sats: number): string {
  if (sats > 8) return 'text-ds-green'
  if (sats >= 4) return 'text-ds-amber'
  return 'text-ds-red'
}

function headingDir(deg: number): string {
  const dirs = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW']
  return dirs[Math.round(deg / 45) % 8]
}

export default function FlightInstruments({ droneState, connected }: Props) {
  const phase     = droneState.flight_phase ?? 'PREFLIGHT'
  const phaseCls  = PHASE_COLOR[phase] ?? PHASE_COLOR.PREFLIGHT
  const battPct   = droneState.battery_pct ?? 100
  const gpsCount  = droneState.gps_sats ?? 12
  const heading   = droneState.heading ?? 0
  const gndSpd    = droneState.groundspeed ?? 0
  const breach    = droneState.geofence_breach ?? false

  if (!connected) {
    return (
      <div className="h-11 flex items-center px-4 bg-ds-panel border-b border-ds-border shrink-0">
        <span className="text-[10px] font-mono text-ds-t3">Flight instruments offline — awaiting connection</span>
      </div>
    )
  }

  return (
    <div className="h-11 flex items-center gap-0 bg-ds-panel border-b border-ds-border shrink-0 overflow-hidden">

      {/* Divider helper */}
      {/* Flight Phase */}
      <div className="flex items-center gap-2 px-3 h-full border-r border-ds-border shrink-0">
        <span className="text-[9px] text-ds-t3 uppercase tracking-widest font-mono">Phase</span>
        <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5 rounded border ${phaseCls}`}>
          {phase}
        </span>
      </div>

      {/* Battery */}
      <div className="flex items-center gap-2 px-3 h-full border-r border-ds-border shrink-0">
        <span className="text-[9px] text-ds-t3 uppercase tracking-widest font-mono">Batt</span>
        <span className={`text-[11px] font-bold font-mono ${batteryColor(battPct)}`}>
          {battPct.toFixed(0)}%
        </span>
        <span className={`text-[10px] font-mono tracking-tighter ${batteryColor(battPct)}`}>
          {batteryBar(battPct)}
        </span>
      </div>

      {/* GPS */}
      <div className="flex items-center gap-2 px-3 h-full border-r border-ds-border shrink-0">
        <span className="text-[9px] text-ds-t3 uppercase tracking-widest font-mono">GPS</span>
        <span className={`text-[11px] font-bold font-mono ${gpsColor(gpsCount)}`}>
          {gpsCount}
        </span>
        <span className={`text-[9px] font-mono ${gpsColor(gpsCount)}`}>
          {gpsQuality(gpsCount)}
        </span>
      </div>

      {/* Ground Speed */}
      <div className="flex items-center gap-2 px-3 h-full border-r border-ds-border shrink-0">
        <span className="text-[9px] text-ds-t3 uppercase tracking-widest font-mono">Gnd Spd</span>
        <span className="text-[11px] font-bold font-mono text-ds-cyan">
          {gndSpd.toFixed(1)}
        </span>
        <span className="text-[9px] text-ds-t3 font-mono">m/s</span>
      </div>

      {/* Heading */}
      <div className="flex items-center gap-2 px-3 h-full border-r border-ds-border shrink-0">
        <span className="text-[9px] text-ds-t3 uppercase tracking-widest font-mono">HDG</span>
        <span className="text-[11px] font-bold font-mono text-ds-t1">
          {heading.toFixed(0)}°
        </span>
        <span className="text-[9px] font-mono text-ds-cyan">
          {headingDir(heading)}
        </span>
      </div>

      {/* Geofence */}
      <div className="flex items-center gap-2 px-3 h-full shrink-0">
        <span className="text-[9px] text-ds-t3 uppercase tracking-widest font-mono">Fence</span>
        {breach ? (
          <span className="text-[10px] font-bold font-mono text-ds-red animate-pulse-fast">
            BREACH
          </span>
        ) : (
          <span className="text-[10px] font-bold font-mono text-ds-green">
            NOMINAL
          </span>
        )}
      </div>
    </div>
  )
}
