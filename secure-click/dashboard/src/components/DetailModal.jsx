// DetailModal.jsx
import React from "react";
import ReactModal from "react-modal";

ReactModal.setAppElement("#root");

export default function DetailModal({ item, onClose }) {
  if (!item) return null;

  // Determine human-readable verdict
  const scoreVal = typeof item.score === "number" ? item.score
                  : typeof item.ml_score_ensemble === "number" ? item.ml_score_ensemble
                  : typeof item.ml_score === "number" ? item.ml_score
                  : null;

  const verdict = (() => {
    if (scoreVal === null) {
      return item.label === 1 ? "Suspicious" : "Safe";
    }
    if (scoreVal < 0.5) return "Safe";
    if (scoreVal >= 0.75) return "Phishing";
    return "Suspicious";
  })();

  // Helper to format percentage
  const fmtPct = (v) => (typeof v === "number" ? (v * 100).toFixed(2) + "%" : "N/A");

  // Get individual ML model scores for the current ensemble (bagging/adaboost/gradboost)
  const mlScores = {};
  if (item.ml_scores_individual && typeof item.ml_scores_individual === "object") {
    mlScores.bagging =
      item.ml_scores_individual.bagging ??
      item.ml_scores_individual.bag ??
      item.ml_scores_individual.bagging_score;
    mlScores.adaboost =
      item.ml_scores_individual.adaboost ??
      item.ml_scores_individual.ada ??
      item.ml_scores_individual.adaboost_score;
    mlScores.gradboost =
      item.ml_scores_individual.gradboost ??
      item.ml_scores_individual.gbdt ??
      item.ml_scores_individual.gradboost_score;
  }

  // ml_used flag and warning
  const mlUsed = item.ml_used === true || typeof item.ml_score_ensemble === "number" || typeof item.ml_score === "number";
  const mlWarning = item.ml_warning || item.ml_warning_message || null;

  // Extract a compact "why" summary from reason + heuristics
  const whySummary = (() => {
    if (!item.reason) return null;
    const parts = String(item.reason)
      .split(/;|\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!parts.length) return null;
    // Show up to first 3 most important bits
    return parts.slice(0, 3);
  })();

  return (
    <ReactModal
      isOpen={!!item}
      onRequestClose={onClose}
      style={{ content: { maxWidth: 760, margin: "auto", inset: "40px", padding: "20px" } }}
    >
      <h3 style={{ marginTop: 0 }}>Scan details</h3>

      <div style={{ marginBottom: 10 }}>
        <div><b>URL:</b> <a href={item.url || "#"} target="_blank" rel="noreferrer">{item.url || "N/A"}</a></div>
        <div><b>Seems to be:</b> <span style={{ fontWeight: 600, marginLeft: 6 }}>{verdict}</span></div>
      </div>

      <div style={{ marginTop: 8 }}>
        <div style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <b>Combined Risk Score:</b>
            <span style={{ fontWeight: 600, fontSize: 16 }}>
              {scoreVal !== null ? (scoreVal * 100).toFixed(2) + "%" : "N/A"}
            </span>
          </div>

          <div style={{
            width: "100%",
            height: 26,
            backgroundColor: "#e5e7eb",
            borderRadius: 14,
            overflow: "hidden",
            position: "relative",
            marginTop: 8
          }}>
            <div style={{
              width: `${scoreVal !== null ? scoreVal * 100 : 0}%`,
              height: "100%",
              background: scoreVal !== null
                ? (scoreVal < 0.3 ? "linear-gradient(90deg,#10b981 0%,#34d399 100%)"
                   : scoreVal < 0.7 ? "linear-gradient(90deg,#f59e0b 0%,#fbbf24 100%)"
                   : "linear-gradient(90deg,#ef4444 0%,#f87171 100%)")
                : "#e5e7eb",
              transition: "width 0.3s ease",
            }}></div>

            <div style={{
              position: "absolute",
              top: "50%",
              left: "50%",
              transform: "translate(-50%, -50%)",
              fontWeight: 600,
              fontSize: 12,
              color: (scoreVal !== null && scoreVal > 0.5) ? "white" : "#1f2937"
            }}>
              {scoreVal !== null ? (scoreVal * 100).toFixed(1) + "%" : "0%"}
            </div>
          </div>
        </div>

        <div style={{ fontSize: 13, color: "#374151" }}>
          <div style={{ marginBottom: 8, padding: 10, backgroundColor: "#f9fafb", borderRadius: 6 }}>
            <div style={{ fontWeight: 600, marginBottom: 6 }}>Machine Learning Scores:</div>
            <div style={{ marginLeft: 8 }}>• <b>Bagging:</b> {fmtPct(mlScores.bagging)}</div>
            <div style={{ marginLeft: 8, marginTop: 4 }}>• <b>AdaBoost:</b> {fmtPct(mlScores.adaboost)}</div>
            <div style={{ marginLeft: 8, marginTop: 4 }}>• <b>GradBoost:</b> {fmtPct(mlScores.gradboost)}</div>

            <div style={{ marginLeft: 8, marginTop: 8 }}>
              • <b>Ensemble ML Score:</b> <span style={{ fontWeight: 600, color: "#111827" }}>
                {typeof item.ml_score_ensemble === "number" ? (item.ml_score_ensemble * 100).toFixed(2) + "%" :
                 typeof item.ml_score === "number" ? (item.ml_score * 100).toFixed(2) + "%" : "N/A"}
              </span>
            </div>
            <div style={{ marginLeft: 8, marginTop: 6 }}>
              • <b>ML used:</b> {mlUsed ? <span style={{ color: "#10b981" }}>Yes</span> : <span style={{ color: "#ef4444" }}>No</span>}
            </div>
            {mlWarning && (
              <div style={{ marginLeft: 8, marginTop: 6, color: "#b45309" }}>
                ⚠️ ML warning: {mlWarning}
              </div>
            )}
          </div>

          <div style={{ marginTop: 6 }}>
            <div style={{ marginBottom: 6 }}><b>Heuristics Score:</b> {typeof item.heuristics_score === "number" ? (item.heuristics_score * 100).toFixed(2) + '%' : (typeof item.score === 'number' ? (item.score * 100).toFixed(2) + '%' : 'N/A')}</div>
          </div>
        </div>
      </div>

      {whySummary && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Why we think this is {verdict}:</div>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: "#374151" }}>
            {whySummary.map((line, idx) => (
              <li key={idx}>{line}</li>
            ))}
          </ul>
        </div>
      )}

      <div style={{ marginTop: 12 }}>
        <div style={{ marginBottom: 6 }}><b>Analysis Parameters / Reason:</b></div>
        <div style={{ marginTop: 4, padding: 12, backgroundColor: "#f5f5f5", borderRadius: 6, fontSize: 13 }}>
          <pre style={{ whiteSpace: "pre-wrap", margin: 0, fontFamily: "inherit" }}>{item.reason || "No analysis parameters available"}</pre>
        </div>
      </div>

      <div style={{ marginTop: 12, display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center" }}>
        {item.google_safe !== undefined && (
          <div><b>Google Safe Browsing:</b> {item.google_safe ? <span style={{ color: "#ef4444" }}>Flagged</span> : <span style={{ color: "#10b981" }}>Not flagged</span>}</div>
        )}

        {item.virustotal_flag !== undefined && (
          <div>
            <b>VirusTotal:</b> {item.virustotal_flag ? (
              <span style={{ color: "#ef4444" }}>Flagged ({item.virustotal_positives || 0}/{item.virustotal_total || 0} engines)</span>
            ) : (
              <span style={{ color: "#10b981" }}>Not flagged</span>
            )}
          </div>
        )}
      </div>

      <div style={{ marginTop: 16, display: "flex", justifyContent: "flex-end" }}>
        <button onClick={onClose} style={{ padding: "8px 12px", borderRadius: 6 }}>Close</button>
      </div>
    </ReactModal>
  );
}
