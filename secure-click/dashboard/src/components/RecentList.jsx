// RecentList.jsx
import React from "react";

function fmtScore(v) {
  return (typeof v === "number") ? v.toFixed(3) : "N/A";
}

function pickScore(row) {
  // Prefer combined 'score' if present (final combined score).
  if (typeof row.score === "number") return row.score;
  // Fallback to ensemble ML score
  if (typeof row.ml_score_ensemble === "number") return row.ml_score_ensemble;
  if (typeof row.ml_score === "number") return row.ml_score;
  return null;
}

function verdictFromScore(score, label) {
  if (score === null) return (label === 1 ? "Suspicious" : "Safe");
  if (score < 0.5) return "Safe";
  if (score >= 0.75) return "Phishing";
  return "Suspicious";
}

function scoreBarStyle(score) {
  const pct = (typeof score === "number") ? Math.max(0, Math.min(100, score * 100)) : 0;
  let bg;
  if (score === null) bg = "#e5e7eb";
  else if (score < 0.3) bg = "linear-gradient(90deg, #10b981 0%, #34d399 100%)";
  else if (score < 0.7) bg = "linear-gradient(90deg, #f59e0b 0%, #fbbf24 100%)";
  else bg = "linear-gradient(90deg, #ef4444 0%, #f87171 100%)";
  return { width: `${pct}%`, height: "100%", background: bg, transition: "width 0.25s ease", borderRadius: 4 };
}

export default function RecentList({ data, onOpenDetail, onRescan, rescanLoadingId }) {
  if (!data || !Array.isArray(data) || data.length === 0) {
    return <div style={{ padding: "20px", textAlign: "center", color: "#666" }}>No data available</div>;
  }

  return (
    <table className="table" style={{ width: "100%", borderCollapse: "collapse" }}>
      <thead>
        <tr>
          <th style={{ textAlign: "left", padding: "8px" }}>URL</th>
          <th style={{ padding: "8px" }}>Score</th>
          <th style={{ padding: "8px" }}>Seems to be</th>
          <th style={{ padding: "8px" }}>Time</th>
          <th style={{ padding: "8px" }}>Action</th>
        </tr>
      </thead>
      <tbody>
        {data.map((row) => {
          // safe unique key: prefer id, fallback to ts+url
          const key = row.id ?? `${row.ts || "no-ts"}_${(row.url || "").slice(0, 40)}`;

          const score = pickScore(row);
          const verdict = verdictFromScore(score, row.label);
          const showMlBadge = row.ml_used === true || typeof row.ml_score_ensemble === "number" || typeof row.ml_score === "number";

          return (
            <tr key={key} style={{ borderTop: "1px solid #efefef" }}>
              <td style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", padding: "8px" }} title={row.url || ""}>
                <a href={row.url || "#"} target="_blank" rel="noreferrer" style={{ color: "#111827", textDecoration: "none" }}>
                  {row.url || "N/A"}
                </a>
                <div style={{ marginTop: 6, display: "flex", gap: 8, alignItems: "center", fontSize: 12, color: "#6b7280" }}>
                  {row.google_safe !== undefined && (
                    <span style={{ padding: "2px 6px", borderRadius: 12, background: row.google_safe ? "#fee2e2" : "#ecfdf5", color: row.google_safe ? "#b91c1c" : "#065f46", fontWeight: 600 }}>
                      GSB: {row.google_safe ? "Flagged" : "OK"}
                    </span>
                  )}
                  {row.virustotal_flag !== undefined && (
                    <span style={{ padding: "2px 6px", borderRadius: 12, background: row.virustotal_flag ? "#fee2e2" : "#ecfdf5", color: row.virustotal_flag ? "#b91c1c" : "#065f46", fontWeight: 600 }}>
                      VT: {row.virustotal_flag ? `${row.virustotal_positives || 0}/${row.virustotal_total || 0}` : "OK"}
                    </span>
                  )}
                  {showMlBadge && <span style={{ padding: "2px 6px", borderRadius: 12, background: "#eef2ff", color: "#3730a3", fontWeight: 600 }}>ML</span>}
                </div>
              </td>

              <td style={{ padding: "8px", width: 200 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ minWidth: 50, textAlign: "left" }}>{fmtScore(score)}</span>
                  <div style={{ width: 120, height: 8, backgroundColor: "#e5e7eb", borderRadius: 4, overflow: "hidden" }}>
                    <div style={scoreBarStyle(score)} />
                  </div>
                </div>
              </td>

              <td style={{ padding: "8px" }}>
                {verdict === "Safe" ? <span className="badge safe">Safe</span> :
                  verdict === "Phishing" ? <span className="badge mal">Phishing</span> :
                    <span className="badge mal">Suspicious</span>}
              </td>

              <td style={{ padding: "8px", whiteSpace: "nowrap" }}>
                {row.ts ? new Date(row.ts * 1000).toLocaleString() : "N/A"}
              </td>

              <td style={{ padding: "8px", display: "flex", gap: 8 }}>
                <button onClick={() => onOpenDetail(row)} aria-label={`Details for ${row.url || "row"}`} style={{ padding: "6px 10px", borderRadius: 6 }}>
                  Details
                </button>

                {onRescan && (
                  <button
                    onClick={() => onRescan(row)}
                    disabled={rescanLoadingId === row.id}
                    style={{
                      padding: "6px 10px",
                      borderRadius: 6,
                      marginLeft: 6,
                      opacity: rescanLoadingId === row.id ? 0.6 : 1,
                      cursor: rescanLoadingId === row.id ? "not-allowed" : "pointer"
                    }}
                    aria-disabled={rescanLoadingId === row.id}
                    aria-label={rescanLoadingId === row.id ? "Rescanning" : `Rescan ${row.url || "row"}`}
                  >
                    {rescanLoadingId === row.id ? "Rescanning..." : "Rescan"}
                  </button>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
