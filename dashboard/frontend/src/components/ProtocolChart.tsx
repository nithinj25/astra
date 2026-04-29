import { useMemo } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from 'recharts'
import type { IDSEvent } from '../App'

interface Props { events: IDSEvent[] }

export default function ProtocolChart({ events }: Props) {
  const data = useMemo(() => {
    const m: Record<string, { pass: number; alert: number; block: number }> = {}
    for (const ev of events) {
      if (!m[ev.packet_type]) m[ev.packet_type] = { pass: 0, alert: 0, block: 0 }
      if (ev.verdict === 'ALLOW') m[ev.packet_type].pass++
      else if (ev.verdict === 'ALERT') m[ev.packet_type].alert++
      else m[ev.packet_type].block++
    }
    return Object.entries(m)
      .map(([type, v]) => ({ type, ...v, total: v.pass + v.alert + v.block }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 8)
  }, [events])

  const topByBlock = useMemo(
    () => data.reduce((a, b) => (b.block > a.block ? b : a), { type: '—', block: 0 }).type,
    [data],
  )

  if (!data.length) {
    return (
      <div className="flex-1 flex items-center justify-center text-ds-t3 text-xs">
        Awaiting traffic…
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col p-3 gap-2 overflow-hidden">
      {/* Legend + summary */}
      <div className="flex items-center gap-4 shrink-0 text-[10px] font-mono">
        <Dot color="bg-ds-green" label="Pass" />
        <Dot color="bg-ds-amber" label="Alert" />
        <Dot color="bg-ds-red"   label="Block" />
        <span className="ml-auto text-ds-t3">
          Most attacked: <span className="text-ds-red">{topByBlock}</span>
        </span>
      </div>

      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 8, bottom: 26, left: 0 }}>
          <CartesianGrid stroke="#1e2a3a" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="type"
            tick={{ fill: '#3d4f63', fontSize: 8, fontFamily: 'monospace' }}
            angle={-30}
            textAnchor="end"
            interval={0}
            axisLine={{ stroke: '#1e2a3a' }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: '#3d4f63', fontSize: 9, fontFamily: 'monospace' }}
            axisLine={{ stroke: '#1e2a3a' }}
            tickLine={false}
            width={28}
          />
          <Tooltip
            cursor={{ fill: 'rgba(59,130,246,0.06)' }}
            contentStyle={{
              background: '#141d2e',
              border: '1px solid #1e2a3a',
              borderRadius: 4,
              fontSize: 11,
              fontFamily: 'monospace',
            }}
            labelStyle={{ color: '#dce3ef', marginBottom: 4 }}
            itemStyle={{ color: '#7f8ea3' }}
            formatter={(value: number, name: string) => [value, name]}
          />
          <Bar dataKey="pass"  name="Pass"  stackId="a" fill="#22c55e" opacity={0.75} isAnimationActive={false} />
          <Bar dataKey="alert" name="Alert" stackId="a" fill="#f59e0b" opacity={0.80} isAnimationActive={false} />
          <Bar dataKey="block" name="Block" stackId="a" fill="#ef4444" opacity={0.85} isAnimationActive={false}
               radius={[2, 2, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

function Dot({ color, label }: { color: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5 text-ds-t3">
      <span className={`w-2 h-2 rounded-sm inline-block ${color}`} />
      {label}
    </span>
  )
}
