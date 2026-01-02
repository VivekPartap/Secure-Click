// App.jsx
import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import RecentList from "./components/RecentList.jsx";
import DetailModal from "./components/DetailModal";

const API = "http://localhost:8000"; // change if needed

export default function App() {
  const [history, setHistory] = useState([]);
  const [filteredHistory, setFilteredHistory] = useState([]);
  const [stats, setStats] = useState({ total: 0, safe: 0, suspicious: 0 });
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState("all"); // "all", "safe", "suspicious"
  const [sortBy, setSortBy] = useState("time_desc"); // "time_desc" | "time_asc" | "score_desc" | "score_asc"
  const [page, setPage] = useState(1);
  const pageSize = 50;
  const [rescanStatus, setRescanStatus] = useState(null);
  const [rescanLoadingId, setRescanLoadingId] = useState(null);
  const [useSafeBrowsing, setUseSafeBrowsing] = useState(false);

  async function fetchStats() {
    try {
      const resp = await axios.get(`${API}/stats`);
      const data = resp.data;
      if (data && typeof data.total === "number") {
        setStats({
          total: data.total,
          safe: data.safe || 0,
          suspicious: data.suspicious || 0,
        });
      }
    } catch (e) {
      console.error("Failed to fetch stats:", e);
      // keep previous stats on error
    }
  }

  async function fetchHistory() {
    try {
      const resp = await axios.get(`${API}/history?limit=200`);
      const data = resp.data;
      if (Array.isArray(data)) {
        // normalize fields for UI convenience
        const normalized = data.map((r) => ({
          ...r,
          // older DB rows might not have ml fields; ensure consistent types
          score: typeof r.score === "number" ? r.score : parseFloat(r.score) || 0,
          ml_used: typeof r.ml_used === "boolean" ? r.ml_used : !!r.ml_score,
          ml_score_ensemble:
            typeof r.ml_score_ensemble === "number"
              ? r.ml_score_ensemble
              : typeof r.ml_score === "number"
              ? r.ml_score
              : 0,
          ml_score_bag: typeof r.ml_score_bag === "number" ? r.ml_score_bag : 0,
          ml_score_ada: typeof r.ml_score_ada === "number" ? r.ml_score_ada : 0,
          ml_score_gb: typeof r.ml_score_gb === "number" ? r.ml_score_gb : 0,
        }));
        setHistory(normalized);
      } else {
        console.error("Invalid /history response:", data);
        setHistory([]);
      }
    } catch (e) {
      console.error("Failed to fetch history:", e);
      if (e.code === "ECONNREFUSED" || e.message?.includes("Network Error")) {
        console.error(
          "Backend server is not running. Start it with: uvicorn backend.app:app --reload --port 8000"
        );
      }
      setHistory([]);
    } finally {
      setLoading(false);
    }
  }

  const filteredAndSorted = useMemo(() => {
    let filtered = [...history];

    // Search by URL
    if (searchQuery.trim()) {
      const lowerQuery = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (item) => item.url && item.url.toLowerCase().includes(lowerQuery)
      );
    }

    // Type filter
    if (filterType === "safe") {
      filtered = filtered.filter((item) => item.label === 0);
    } else if (filterType === "suspicious") {
      filtered = filtered.filter((item) => item.label === 1);
    }

    // Sorting
    filtered.sort((a, b) => {
      const scoreA = typeof a.score === "number" ? a.score : 0;
      const scoreB = typeof b.score === "number" ? b.score : 0;
      const tsA = a.ts || 0;
      const tsB = b.ts || 0;
      switch (sortBy) {
        case "score_desc":
          return scoreB - scoreA;
        case "score_asc":
          return scoreA - scoreB;
        case "time_asc":
          return tsA - tsB;
        case "time_desc":
        default:
          return tsB - tsA;
      }
    });

    return filtered;
  }, [history, searchQuery, filterType, sortBy]);

  const pagedData = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredAndSorted.slice(start, start + pageSize);
  }, [filteredAndSorted, page]);

  const totalPages = Math.max(1, Math.ceil(filteredAndSorted.length / pageSize));

  function handleExportCsv() {
    if (!filteredAndSorted.length) return;
    const header = [
      "id",
      "url",
      "score",
      "label",
      "heuristics_score",
      "google_safe",
      "virustotal_flag",
      "virustotal_positives",
      "virustotal_total",
      "ts",
      "reason",
    ];
    const rows = filteredAndSorted.map((r) => [
      r.id ?? "",
      `"${(r.url || "").replace(/"/g, '""')}"`,
      typeof r.score === "number" ? r.score.toFixed(4) : "",
      r.label ?? "",
      typeof r.heuristics_score === "number" ? r.heuristics_score.toFixed(4) : "",
      r.google_safe ? "1" : "0",
      r.virustotal_flag ? "1" : "0",
      r.virustotal_positives ?? 0,
      r.virustotal_total ?? 0,
      r.ts ?? "",
      `"${(r.reason || "").replace(/"/g, '""').replace(/\r?\n/g, " ")}"`,
    ]);
    const csv = [header.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `secure-click-history-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  async function rescanUrl(entry) {
    const targetUrl = entry?.url;
    if (!targetUrl) {
      setRescanStatus({ type: "error", message: "Cannot rescan: URL missing." });
      return;
    }

    setRescanLoadingId(entry.id ?? null);
    setRescanStatus({
      type: "info",
      message: `Requesting rescan for ${targetUrl} ${useSafeBrowsing ? "(Safe Browsing ON)" : ""}`,
    });

    try {
      const resp = await axios.post(`${API}/predict`, {
        url: targetUrl,
        run_safe_browsing: Boolean(useSafeBrowsing),
      });
      const labelText = resp.data.label === 1 ? "Suspicious" : "Safe";
      setRescanStatus({
        type: "success",
        message: `Rescan complete – ${labelText} (score ${(resp.data.score * 100).toFixed(1)}%)`,
      });
      // refresh stats & history
      await fetchStats();
      await fetchHistory();
      // open detail view for the freshly scanned row (try to pick matching latest record)
      if (resp.data && resp.data.ts) {
        const matching = (await axios.get(`${API}/history?limit=10`)).data || [];
        const match = matching.find((r) => r.ts === resp.data.ts || r.url === resp.data.url);
        if (match) setDetail(match);
      }
    } catch (error) {
      console.error("Failed to rescan URL:", error);
      const detailMsg =
        error?.response?.data?.detail || error?.message || "Please try again shortly.";
      setRescanStatus({
        type: "error",
        message: `Rescan failed for ${targetUrl}. ${detailMsg}`,
      });
    } finally {
      setRescanLoadingId(null);
    }
  }

  // Reset to first page when filters change
  useEffect(() => {
    setPage(1);
  }, [searchQuery, filterType, sortBy]);

  useEffect(() => {
    fetchStats();
    fetchHistory();
    const t = setInterval(() => {
      fetchStats();
      fetchHistory();
    }, 15_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!rescanStatus) return;
    const timer = window.setTimeout(() => setRescanStatus(null), 6000);
    return () => window.clearTimeout(timer);
  }, [rescanStatus]);

  return (
    <div className="container">
      <div className="header">
        <h1>Secure-Click Dashboard</h1>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <button
            className="card"
            onClick={() => {
              fetchStats();
              fetchHistory();
            }}
            style={{ padding: "8px 16px", cursor: "pointer" }}
          >
            Refresh
          </button>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
            <input
              type="checkbox"
              checked={useSafeBrowsing}
              onChange={(e) => setUseSafeBrowsing(e.target.checked)}
            />
            Use Google Safe Browsing for rescans
          </label>
        </div>
      </div>

      <div className="grid">
        <div className="card">
          <h4>Total Scans</h4>
          <div style={{ fontSize: 28, marginTop: 8 }}>{stats.total}</div>
        </div>
        <div className="card">
          <h4>Safe</h4>
          <div style={{ fontSize: 28, marginTop: 8, color: "#065f46" }}>{stats.safe}</div>
        </div>
        <div className="card">
          <h4>Suspicious</h4>
          <div style={{ fontSize: 28, marginTop: 8, color: "#9f1239" }}>{stats.suspicious}</div>
        </div>
      </div>

      <div className="card">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "16px",
          }}
        >
          <div>
            <h3 style={{ margin: 0 }}>Recent Sites</h3>
            <div style={{ fontSize: "12px", color: "#666", marginTop: "4px" }}>
              Showing up to {history.length} most recent scans (Total: {stats.total} scans in database)
            </div>
          </div>

          <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap", justifyContent: "flex-end" }}>
            <input
              type="text"
              placeholder="Search URL..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                padding: "8px 12px",
                border: "1px solid #ddd",
                borderRadius: "6px",
                fontSize: "14px",
                minWidth: "180px",
              }}
            />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              style={{ padding: "6px 8px", borderRadius: 6, border: "1px solid #ddd", fontSize: 13 }}
            >
              <option value="time_desc">Newest first</option>
              <option value="time_asc">Oldest first</option>
              <option value="score_desc">Score high → low</option>
              <option value="score_asc">Score low → high</option>
            </select>
            <div style={{ display: "flex", gap: "4px" }}>
              <button
                onClick={() => setFilterType("all")}
                className={filterType === "all" ? "pill pill-active" : "pill"}
              >
                All
              </button>
              <button
                onClick={() => setFilterType("safe")}
                className={filterType === "safe" ? "pill pill-safe" : "pill"}
              >
                Safe
              </button>
              <button
                onClick={() => setFilterType("suspicious")}
                className={filterType === "suspicious" ? "pill pill-suspicious" : "pill"}
              >
                Suspicious
              </button>
            </div>
            <button
              onClick={handleExportCsv}
              style={{
                padding: "6px 10px",
                borderRadius: 6,
                border: "1px solid #e5e7eb",
                background: "#f9fafb",
                fontSize: 12,
                cursor: filteredAndSorted.length ? "pointer" : "not-allowed",
                opacity: filteredAndSorted.length ? 1 : 0.6,
              }}
              disabled={!filteredAndSorted.length}
            >
              Export CSV
            </button>
          </div>
        </div>

        {rescanStatus && (
          <div
            style={{
              marginBottom: "12px",
              padding: "10px",
              borderRadius: "8px",
              backgroundColor:
                rescanStatus.type === "error"
                  ? "#fee2e2"
                  : rescanStatus.type === "success"
                  ? "#ecfdf5"
                  : "#e0f2fe",
              color:
                rescanStatus.type === "error"
                  ? "#991b1b"
                  : rescanStatus.type === "success"
                  ? "#065f46"
                  : "#0369a1",
              border:
                rescanStatus.type === "error"
                  ? "1px solid #f87171"
                  : "1px solid rgba(59, 130, 246, 0.2)",
              fontSize: "14px",
            }}
          >
            {rescanStatus.message}
          </div>
        )}

        {loading ? (
          <div>Loading...</div>
        ) : history.length === 0 ? (
          <div style={{ padding: "20px", textAlign: "center", color: "#666" }}>
            <p>No scan history found.</p>
            <p style={{ fontSize: "12px", marginTop: "8px" }}>
              Make sure the backend server is running on {API}
            </p>
          </div>
        ) : filteredAndSorted.length === 0 ? (
          <div style={{ padding: "20px", textAlign: "center", color: "#666" }}>
              <p>No results found matching your search/filter criteria.</p>
            <p style={{ fontSize: "12px", marginTop: "8px" }}>Try adjusting your search query or filter.</p>
          </div>
        ) : (
          <>
            <div style={{ marginBottom: "12px", fontSize: "14px", color: "#666" }}>
              Showing {pagedData.length} of {filteredAndSorted.length} filtered scans
              {stats.total > history.length && (
                <span style={{ marginLeft: "8px", fontStyle: "italic" }}>
                  (Total: {stats.total} scans in database)
                </span>
              )}
            </div>

            <RecentList
              data={pagedData}
              onOpenDetail={(d) => setDetail(d)}
              onRescan={rescanUrl}
              rescanLoadingId={rescanLoadingId}
            />

            <div style={{ marginTop: 12, display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 13 }}>
              <div>
                Page {page} of {totalPages}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  style={{
                    padding: "6px 10px",
                    borderRadius: 6,
                    border: "1px solid #e5e7eb",
                    background: page === 1 ? "#f9fafb" : "white",
                    cursor: page === 1 ? "not-allowed" : "pointer",
                  }}
                >
                  Prev
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  style={{
                    padding: "6px 10px",
                    borderRadius: 6,
                    border: "1px solid #e5e7eb",
                    background: page >= totalPages ? "#f9fafb" : "white",
                    cursor: page >= totalPages ? "not-allowed" : "pointer",
                  }}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      <DetailModal item={detail} onClose={() => setDetail(null)} />
    </div>
  );
}
