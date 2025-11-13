import React from "react";

export default function RecentList({ data, onOpenDetail }) {
  if (!data || !Array.isArray(data) || data.length === 0) {
    return <div style={{padding: '20px', textAlign: 'center', color: '#666'}}>No data available</div>;
  }
  
  return (
    <table className="table">
      <thead>
        <tr><th>URL</th><th>Score</th><th>Seems to be</th><th>Time</th><th>Action</th></tr>
      </thead>
      <tbody>
        {data.map(row => (
          <tr key={row.id || Math.random()}>
            <td style={{maxWidth:420, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}} title={row.url || ''}>
              <a href={row.url || '#'} target="_blank" rel="noreferrer">{row.url || 'N/A'}</a>
            </td>
            <td>{typeof row.score === 'number' ? row.score.toFixed(3) : 'N/A'}</td>
            <td>
              {row.label===1 ? <span className="badge mal">Suspicious</span> : <span className="badge safe">Safe</span>}
            </td>
            <td>{row.ts ? new Date(row.ts * 1000).toLocaleString() : 'N/A'}</td>
            <td><button onClick={() => onOpenDetail(row)}>Details</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
