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
  PARAM_TAMPER: {
    title:    'Critical Parameter Tampering',
    severity: 'CRITICAL',
    category: 'Configuration Attack',
    impact:
      'Adversary sending PARAM_SET to modify flight-critical parameters — disabling geofencing (FENCE_ACTION=0), '
      + 'GCS failsafe (FS_GCS_ENABLE=0), or arming checks (ARMING_CHECK=0). '
      + 'Successful modification removes key safety constraints from the autopilot.',
    recommendation: 'Parameter change blocked. Audit current parameter set against known-good baseline.',
    mitre: 'ICS T0836 — Modify Parameter',
    cvss:  9.3,
    fields: [
      { label: 'Message ID',      desc: 'PARAM_SET (23)' },
      { label: 'Target',          desc: 'Autopilot parameter store' },
      { label: 'Common targets',  desc: 'FENCE_ACTION, FS_GCS_ENABLE, ARMING_CHECK' },
      { label: 'Source',          desc: 'Unregistered — not in trusted GCS registry' },
    ],
  },
  MISSION_INJECT: {
    title:    'Hostile Waypoint Injection',
    severity: 'CRITICAL',
    category: 'Mission Manipulation',
    impact:
      'MISSION_ITEM or MISSION_COUNT received from unregistered source. '
      + 'Attacker can upload a replacement flight plan directing the drone to a hostile location, '
      + 'into restricted airspace, or into a physical hazard — without operator knowledge.',
    recommendation: 'Mission upload blocked. Current mission plan preserved.',
    mitre: 'ICS T0840 — Network Connection Enumeration',
    cvss:  9.0,
    fields: [
      { label: 'Message ID',   desc: 'MISSION_ITEM (39) / MISSION_COUNT (44)' },
      { label: 'Waypoint cmd', desc: 'MAV_CMD_NAV_WAYPOINT (16)' },
      { label: 'Frame',        desc: 'MAV_FRAME_GLOBAL_RELATIVE_ALT (3)' },
      { label: 'Target',       desc: 'Hostile coordinates outside operational zone' },
    ],
  },
  HEARTBEAT_SPOOF: {
    title:    'GCS Identity Spoofing',
    severity: 'HIGH',
    category: 'Trust Escalation',
    impact:
      'Single source IP sending HEARTBEAT packets with multiple system IDs. '
      + 'Attacker is attempting to register multiple fake GCS identities to gain trusted status, '
      + 'enabling subsequent unauthorized commands that would be accepted by the IDS.',
    recommendation: 'Spoofed system IDs blocked from trust registry. Only canonical GCS sys_id=1 accepted.',
    mitre: 'ICS T0886 — Remote System Discovery',
    cvss:  7.5,
    fields: [
      { label: 'Message ID',    desc: 'HEARTBEAT (0)' },
      { label: 'Anomaly',       desc: 'Multiple sys_ids from same IP within 30s' },
      { label: 'Goal',          desc: 'Register fake GCS as trusted source' },
      { label: 'Window',        desc: '30 second observation window' },
    ],
  },
  GEOFENCE_BREACH: {
    title:    'Geofence Boundary Violation',
    severity: 'HIGH',
    category: 'Spatial Anomaly',
    impact:
      'GPS position update places the drone outside the 300m operational geofence. '
      + 'This may indicate a slow-drift GPS spoofing attack that passed GPS_JUMP detection '
      + 'by using small incremental position changes to gradually move the drone outside the safe zone.',
    recommendation:
      'Alert raised. Consider activating RTL (Return to Launch) and cross-validating with IMU dead-reckoning.',
    mitre: 'ICS T0856 — Spoof Reporting Message',
    cvss:  8.0,
    fields: [
      { label: 'Geofence',    desc: '300m radius from home position' },
      { label: 'Home',        desc: '37.7749°N, 122.4194°W' },
      { label: 'Detection',   desc: 'Haversine distance from home exceeds limit' },
      { label: 'Attack type', desc: 'Slow-drift GPS spoofing (sub-50m increments)' },
    ],
  },
}
