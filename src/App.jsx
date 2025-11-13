import React, { useEffect, useState } from "react";
import axios from "axios";
import RecentList from "./components/RecentList.jsx";
import DetailModal from "./components/DetailModal";

const API = "http://localhost:8000"; // change if needed

export default function App() {
  const [history, setHistory] = useState([]);
  const [filteredHistory, setFilteredHistory] = useState([]);
  const [stats, setStats] = useState({total:0, safe:0, suspicious:0});
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState("all"); // "all", "safe", "suspicious"

  async function fetchHistory() {
    try {
      const resp = await axios.get(`${API}/history?limit=200`);
      const data = resp.data;
      if (Array.isArray(data)) {
        setHistory(data);
        const total = data.length;
        const suspicious = data.filter(d => d.label===1).length;
        setStats({ total, suspicious, safe: total - suspicious });
        applyFilters(data, searchQuery, filterType);
      } else {
        console.error("Invalid response format:", data);
        setHistory([]);
        setStats({ total: 0, suspicious: 0, safe: 0 });
      }
    } catch (e) {
      console.error("Failed to fetch history:", e);
      if (e.code === 'ECONNREFUSED' || e.message?.includes('Network Error')) {
        console.error("Backend server is not running. Please start it with: uvicorn backend.app:app --reload --port 8000");
      }
      setHistory([]);
      setStats({ total: 0, suspicious: 0, safe: 0 });
    } finally {
      setLoading(false);
    }
  }

  function applyFilters(data, query, filter) {
    let filtered = [...data];
    
    // Apply search query filter
    if (query.trim()) {
      const lowerQuery = query.toLowerCase();
      filtered = filtered.filter(item => 
        item.url && item.url.toLowerCase().includes(lowerQuery)
      );
    }
    
    // Apply type filter (safe/suspicious/all)
    if (filter === "safe") {
      filtered = filtered.filter(item => item.label === 0);
    } else if (filter === "suspicious") {
      filtered = filtered.filter(item => item.label === 1);
    }
    // "all" means no additional filtering
    
    setFilteredHistory(filtered);
  }

  useEffect(() => {
    applyFilters(history, searchQuery, filterType);
  }, [searchQuery, filterType, history]);

  useEffect(() => {
    fetchHistory();
    const t = setInterval(fetchHistory, 15_000); // refresh every 15s
    return () => clearInterval(t);
  }, []);

  return (
    <div className="container">
      <div className="header">
        <h1>Secure-Click Dashboard</h1>
        <div>
          <button className="card" onClick={fetchHistory}>Refresh</button>
        </div>
      </div>

      <div className="grid">
        <div className="card">
          <h4>Total Scans</h4>
          <div style={{fontSize:28, marginTop:8}}>{stats.total}</div>
        </div>
        <div className="card">
          <h4>Safe</h4>
          <div style={{fontSize:28, marginTop:8, color:'#065f46'}}>{stats.safe}</div>
        </div>
        <div className="card">
          <h4>Suspicious</h4>
          <div style={{fontSize:28, marginTop:8, color:'#9f1239'}}>{stats.suspicious}</div>
        </div>
      </div>

      <div className="card">
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px'}}>
          <h3 style={{margin: 0}}>Recent Sites</h3>
          <div style={{display: 'flex', gap: '8px', alignItems: 'center'}}>
            <input
              type="text"
              placeholder="Search URL..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                padding: '8px 12px',
                border: '1px solid #ddd',
                borderRadius: '6px',
                fontSize: '14px',
                minWidth: '200px'
              }}
            />
            <div style={{display: 'flex', gap: '4px'}}>
              <button
                onClick={() => setFilterType("all")}
                style={{
                  padding: '6px 12px',
                  border: '1px solid #ddd',
                  borderRadius: '6px',
                  backgroundColor: filterType === "all" ? '#3b82f6' : 'white',
                  color: filterType === "all" ? 'white' : '#333',
                  cursor: 'pointer',
                  fontSize: '13px'
                }}
              >
                All
              </button>
              <button
                onClick={() => setFilterType("safe")}
                style={{
                  padding: '6px 12px',
                  border: '1px solid #ddd',
                  borderRadius: '6px',
                  backgroundColor: filterType === "safe" ? '#065f46' : 'white',
                  color: filterType === "safe" ? 'white' : '#065f46',
                  cursor: 'pointer',
                  fontSize: '13px'
                }}
              >
                Safe
              </button>
              <button
                onClick={() => setFilterType("suspicious")}
                style={{
                  padding: '6px 12px',
                  border: '1px solid #ddd',
                  borderRadius: '6px',
                  backgroundColor: filterType === "suspicious" ? '#9f1239' : 'white',
                  color: filterType === "suspicious" ? 'white' : '#9f1239',
                  cursor: 'pointer',
                  fontSize: '13px'
                }}
              >
                Suspicious
              </button>
            </div>
          </div>
        </div>
        {loading ? (
          <div>Loading...</div>
        ) : history.length === 0 ? (
          <div style={{padding: '20px', textAlign: 'center', color: '#666'}}>
            <p>No scan history found.</p>
            <p style={{fontSize: '12px', marginTop: '8px'}}>
              Make sure the backend server is running on http://localhost:8000
            </p>
          </div>
        ) : filteredHistory.length === 0 ? (
          <div style={{padding: '20px', textAlign: 'center', color: '#666'}}>
            <p>No results found matching your search/filter criteria.</p>
            <p style={{fontSize: '12px', marginTop: '8px'}}>
              Try adjusting your search query or filter.
            </p>
          </div>
        ) : (
          <>
            <div style={{marginBottom: '12px', fontSize: '14px', color: '#666'}}>
              Showing {filteredHistory.length} of {history.length} results
            </div>
            <RecentList data={filteredHistory} onOpenDetail={d => setDetail(d)} />
          </>
        )}
      </div>

      <DetailModal item={detail} onClose={() => setDetail(null)} />
    </div>
  );
}
