import React from 'react';

const getSeverityStyle = (severity) => {
  switch (severity) {
    case 'Critical': return 'bg-red-500';
    case 'High': return 'bg-orange-500';
    case 'Medium': return 'bg-amber-500';
    default: return 'bg-emerald-500';
  }
};

const AlertDetail = ({ event, onBack }) => {
  if (!event) return null;

  const fi = event.flow_info || {};
  const corr = event.correlation || {};
  const similar = event.similar_incidents || [];

  return (
    <div className="space-y-5">
      <button onClick={onBack} className="inline-flex items-center gap-2 text-sm font-medium text-slate-600 hover:text-slate-900">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg>
        Back to Dashboard
      </button>

      {/* Header */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
        <div className="flex flex-wrap justify-between items-start gap-4">
          <div className="flex items-start gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${getSeverityStyle(event.severity)}`}>
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-900">{event.attack_type}</h2>
              <p className="text-xs text-slate-500">Event #{event.id} &bull; {event.source}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`px-3 py-1 rounded-lg text-xs font-medium text-white ${getSeverityStyle(event.severity)}`}>{event.severity}</span>
            <span className="text-xs text-slate-500">{event.timestamp ? new Date(event.timestamp).toLocaleString() : ''}</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Detection Details */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-900 mb-3">Detection Details</h3>
          <div className="space-y-2.5">
            {[
              ['Source / Host', event.host],
              ['Confidence', `${(event.confidence * 100).toFixed(2)}%`],
              ['Model', event.source.includes('Network') ? 'MLP (CICIDS2017)' : 'CNN-LSTM (BGL)'],
              ['Src IP', fi.src_ip || 'N/A'],
              ['Dst IP', fi.dst_ip || 'N/A'],
              ['Dst Port', fi.dst_port || 'N/A'],
              ['Protocol', fi.protocol || 'N/A'],
              ['Packets', fi.packets || 'N/A'],
              ['Bytes', fi.bytes || 'N/A'],
              ['Ground Truth', event.true_label || 'N/A'],
            ].map(([label, val]) => (
              <div key={label} className="flex justify-between py-1.5 border-b border-slate-50 last:border-0">
                <span className="text-xs text-slate-500">{label}</span>
                <span className="text-xs font-medium text-slate-900 font-mono">{val}</span>
              </div>
            ))}
          </div>
        </div>

        {/* XAI Section */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-900 mb-3">Explainable AI</h3>
          <div className="space-y-4">
            {event.explanation?.shap && Object.keys(event.explanation.shap).length > 0 && (
              <div>
                <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">SHAP Feature Impact</h4>
                <div className="space-y-1.5">
                  {Object.entries(event.explanation.shap).map(([feature, value]) => (
                    <div key={feature} className="flex items-center gap-2">
                      <div className="w-2/5 text-[11px] text-slate-600 truncate">{feature}</div>
                      <div className="flex-1 h-4 bg-slate-100 rounded-full overflow-hidden relative">
                        <div className={`absolute h-full rounded-full ${value > 0 ? 'bg-blue-500' : 'bg-rose-400'}`}
                          style={{ width: `${Math.min(Math.abs(value) * 200, 100)}%`, left: value < 0 ? `${100 - Math.min(Math.abs(value) * 200, 100)}%` : '0' }} />
                      </div>
                      <div className="w-14 text-right text-[11px] font-mono text-slate-600">{value > 0 ? '+' : ''}{typeof value === 'number' ? value.toFixed(4) : value}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {event.explanation?.lime && (
              <div>
                <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">LIME / Explanation</h4>
                <div className="bg-slate-50 rounded-lg p-3 border border-slate-100">
                  <p className="text-xs text-slate-700">{event.explanation.lime}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Correlation */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-900 mb-3">Hybrid Correlation</h3>
          {corr.correlated ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 bg-violet-100 text-violet-700 rounded-full text-xs font-medium">Correlated</span>
                <span className="text-xs text-slate-500">{corr.count} related events</span>
              </div>
              <div className="bg-violet-50 rounded-lg p-3 border border-violet-100">
                <p className="text-xs text-violet-800">{corr.summary}</p>
              </div>
              {corr.severity && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-500">Combined Severity:</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium text-white ${getSeverityStyle(corr.severity)}`}>{corr.severity}</span>
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">No correlated events found in the time window.</p>
          )}
        </div>

        {/* Historical Incidents */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
          <h3 className="text-sm font-semibold text-slate-900 mb-3">Historical Similar Incidents</h3>
          {similar.length > 0 ? (
            <div className="space-y-2">
              {similar.map((inc, i) => (
                <div key={i} className="bg-slate-50 rounded-lg p-2.5 border border-slate-100">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-medium text-slate-800">{inc.attack_type}</span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded">{(inc.similarity * 100).toFixed(0)}% similar</span>
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-500 mt-1">
                    <span>{inc.src_ip} → {inc.dst_ip}</span>
                    <span>{inc.datetime ? new Date(inc.datetime).toLocaleString() : ''}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">No similar incidents in history yet.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertDetail;
