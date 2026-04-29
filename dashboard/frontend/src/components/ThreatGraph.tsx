import {
  ComposedChart, Line, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, ReferenceLine, ResponsiveContainer,
} from 'recharts'

interface Props { scores: { t: number; v: number }[] }

const THRESHOLD = 0.15

function CustomTooltip({ active, payload }: { active?: boolean; payload?: Array<{ value: number }> }) {
  if (!active || !payload?.length) return null
  const v = payload[0].value
  return (
    <div className="bg-ds-panel2 border border-ds-border px-2.5 py-1.5 text-[10px] font-mono rounded shadow-lg">
      <div className="text-ds-t3 text-[9px] mb-0.5">Isolation Forest</div>
      <div className={v > THRESHOLD ? 'text-ds-red font-bold' : 'text-ds-green'}>
        score {v.toFixed(4)}
      </div>
      <div className="text-ds-t3 text-[9px] mt-0.5">
        {v > 0.45 ? 'Critical anomaly' : v > THRESHOLD ? 'Anomalous' : 'Nominal'}
      </div>
    </div>
  )
}

export default function ThreatGraph({ scores }: Props) {
  const now  = Date.now()
  const data = scores
    .filter(s => now - s.t <= 60_000)
    .map(s => ({ t: -((now - s.t) / 1000).toFixed(1), v: s.v }))
    .reverse()

  const latest = data.at(-1)?.v ?? 0
  const peak   = Math.max(0, ...data.map(d => d.v))
  const maxDom = Math.min(1, Math.max(0.3, peak + 0.06))

  return (
    <div className="h-full flex flex-col px-3 py-2 gap-1.5">

      {/* Summary row */}
      <div className="flex items-center gap-5 shrink-0 text-[10px] font-mono">
        <span className="text-ds-t3">
          Current:{' '}
          <span className={latest > 0.45 ? 'text-ds-red font-bold' : latest > THRESHOLD ? 'text-ds-amber' : 'text-ds-green'}>
            {latest.toFixed(4)}
          </span>
        </span>
        <span className="text-ds-t3">
          Peak: <span className="text-ds-amber">{peak.toFixed(4)}</span>
        </span>
        <span className="text-ds-t3">
          Threshold: <span className="text-ds-t2">{THRESHOLD}</span>
        </span>
        <span className="ml-auto text-ds-t3">n={data.length}</span>
      </div>

      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={data} margin={{ top: 4, right: 10, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="#1e2a3a" strokeDasharray="3 3" />

          <XAxis
            dataKey="t"
            tick={{ fill: '#3d4f63', fontSize: 9, fontFamily: 'monospace' }}
            tickFormatter={v => `${v}s`}
            interval="preserveStartEnd"
            axisLine={{ stroke: '#1e2a3a' }}
            tickLine={false}
          />
          <YAxis
            domain={[0, maxDom]}
            tick={{ fill: '#3d4f63', fontSize: 9, fontFamily: 'monospace' }}
            tickFormatter={v => v.toFixed(2)}
            width={34}
            axisLine={{ stroke: '#1e2a3a' }}
            tickLine={false}
          />

          <Tooltip content={<CustomTooltip />} />

          <ReferenceLine
            y={THRESHOLD}
            stroke="#f59e0b"
            strokeDasharray="5 3"
            strokeWidth={1}
            label={{
              value: 'anomaly threshold',
              fill: '#f59e0b',
              fontSize: 8,
              position: 'insideTopRight',
              fontFamily: 'monospace',
            }}
          />

          {/* Subtle fill under curve */}
          <Area
            type="monotone"
            dataKey="v"
            fill="rgba(59,130,246,0.06)"
            stroke="none"
            isAnimationActive={false}
          />

          {/* Score line */}
          <Line
            type="monotone"
            dataKey="v"
            stroke="#3b82f6"
            strokeWidth={1.5}
            dot={false}
            activeDot={{ r: 3, fill: '#3b82f6', strokeWidth: 0 }}
            isAnimationActive={false}
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}
