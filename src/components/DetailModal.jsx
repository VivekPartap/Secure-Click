import React from "react";
import ReactModal from "react-modal";

ReactModal.setAppElement("#root");

export default function DetailModal({ item, onClose }) {
  if (!item) return null;
  return (
    <ReactModal isOpen={!!item} onRequestClose={onClose} style={{content:{maxWidth:700, margin:'auto'}}}>
      <h3>Scan details</h3>
      <div><b>URL:</b> <a href={item.url || '#'} target="_blank" rel="noreferrer">{item.url || 'N/A'}</a></div>
      <div><b>Seems to be:</b> {item.label === 1 ? "Suspicious" : "Safe"}</div>
      <div style={{marginTop:8}}>
        <div><b>Combined Risk Score:</b> {typeof item.score === 'number' ? (item.score * 100).toFixed(2) + '%' : 'N/A'}</div>
        <div style={{marginTop:4, fontSize: '13px', color: '#666'}}>
          <div>• <b>ML Model Score:</b> {typeof item.ml_score === 'number' ? (item.ml_score * 100).toFixed(2) + '%' : typeof item.score === 'number' ? (item.score * 100).toFixed(2) + '%' : 'N/A'}</div>
          <div style={{marginTop:2}}>• <b>Heuristics Score:</b> {typeof item.heuristics_score === 'number' ? (item.heuristics_score * 100).toFixed(2) + '%' : typeof item.score === 'number' ? (item.score * 100).toFixed(2) + '%' : 'N/A'}</div>
        </div>
      </div>
      <div style={{marginTop:8}}><b>Analysis Parameters:</b></div>
      <div style={{marginTop:4, padding: '10px', backgroundColor: '#f5f5f5', borderRadius: '4px', fontSize: '13px'}}>
        <pre style={{whiteSpace:"pre-wrap", margin: 0, fontFamily: 'inherit'}}>{item.reason || 'No analysis parameters available'}</pre>
      </div>
      {item.google_safe !== undefined && (
        <div style={{marginTop:8}}><b>Google Safe Browsing:</b> {item.google_safe ? 'Flagged' : 'Not flagged'}</div>
      )}
      <div style={{marginTop:12}}>
        <button onClick={onClose}>Close</button>
      </div>
    </ReactModal>
  );
}
