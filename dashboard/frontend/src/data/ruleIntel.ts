export interface RuleInfo {
  title:          string
  severity:       'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  category:       string
  impact:         string
  recommendation: string
  mitre:          string
  cvss:           number
  fields:         { label: string; desc: string }[]
}

export const RULE_INTEL: Record<string, RuleInfo> = {
  UNTRUSTED_ARM: {
    title:          'Unauthorized Motor Arming',
    severity:       'CRITICAL',
    category:       'Command Injection',
    impact:
      'Rogue COMMAND_LONG(MAV_CMD_COMPONENT_ARM_DISARM=400) received from an unregistered GCS source. '
      + 'Unauthorized motor arming activates propulsion without operator consent — '
      + 'creating an immediate physical hazard to nearby personnel and risk of uncontrolled flyaway.',
    recommendation:
      'Source quarantined. Legitimate GCS must re-register via heartbeat on trusted port 14552.',
    mitre: 'ICS T0883 — Unauthorized Command Message',
    cvss:  9.1,
    fields: [
      { label: 'Command ID',     desc: 'MAV_CMD_COMPONENT_ARM_DISARM (400)' },
      { label: 'Target System',  desc: 'Broadcast (255) or specific autopilot' },
      { label: 'Param 1',        desc: '1.0 = ARM, 0.0 = DISARM' },
      { label: 'Source Port',    desc: 'Ephemeral — not in trusted registry' },
    ],
  },
  GPS_JUMP: {
    title:          'GPS Coordinate Injection',
    severity:       'HIGH',
    category:       'Sensor Spoofing',
    impact:
      'GPS_INPUT packet contains a position delta >50 m within a single telemetry cycle — '
      + 'physically impossible for the flight envelope. '
      + 'Forged coordinates hijack the autopilot navigation stack, '
      + 'enabling adversary-directed flight into restricted or hazardous airspace.',
    recommendation:
      'GPS_INPUT blocked. Autopilot falls back to IMU dead-reckoning until next trusted fix.',
    mitre: 'ICS T0856 — Spoof Reporting Message',
    cvss:  8.5,
    fields: [
      { label: 'Message ID',     desc: 'GPS_INPUT (232)' },
      { label: 'Fix Type',       desc: '3D fix (type 3) — injected' },
      { label: 'Position Delta', desc: '>50 m from last known good position' },
      { label: 'Timestamp',      desc: 'GPS time-of-week manipulated' },
    ],
  },
  UNEXPECTED_MODE_CHANGE: {
    title:          'Unauthorized Mode Transition',
    severity:       'HIGH',
    category:       'State Manipulation',
    impact:
      'SET_MODE command received from an unregistered controller. '
      + 'Adversary may force RTL or LAND override to redirect the flight path, '
      + 'or switch to GUIDED mode to inject arbitrary waypoints without operator knowledge.',
    recommendation: 'Mode change quarantined. Current operational flight mode preserved.',
    mitre: 'ICS T0855 — Unauthorized Mode Change',
    cvss:  7.8,
    fields: [
      { label: 'Message ID',    desc: 'SET_MODE (11)' },
      { label: 'Base Mode',     desc: 'MAV_MODE_FLAG_CUSTOM_MODE_ENABLED (1)' },
      { label: 'Custom Mode',   desc: 'Injected mode value' },
      { label: 'Source',        desc: 'Not in trusted GCS registry' },
    ],
  },
  RATE_LIMIT: {
    title:          'MAVLink Flood (Protocol DoS)',
    severity:       'MEDIUM',
    category:       'Denial of Service',
    impact:
      'Packet rate exceeded 20 pkt/s from a single source — saturating the serial MAVLink channel. '
      + 'Sustained flood delays legitimate GCS telemetry uplinks '
      + 'and may trigger the flight-controller watchdog failsafe.',
    recommendation:
      'Source rate-limited by IDS proxy. Monitor for distributed multi-source amplification.',
    mitre: 'ICS T0814 — Denial of Service',
    cvss:  6.5,
    fields: [
      { label: 'Rate',        desc: '>20 pkt/s (hard limit)' },
      { label: 'Protocol',    desc: 'MAVLink v2 over UDP' },
      { label: 'Effect',      desc: 'Link budget saturation, GCS timeout' },
      { label: 'Source',      desc: 'Single IP, high-frequency burst' },
    ],
  },
}
