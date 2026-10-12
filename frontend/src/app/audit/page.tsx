"use client";

import React, { useEffect, useState } from "react";
import {
  getAuditLog,
  verifyAuditChain,
  AuditRecord,
  AuditVerifyResponse,
} from "@/lib/api";

export default function SingleScreenAuditPage() {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const records = await getAuditLog(50, 0);
      setLogs(records);
      if (records.length > 0 && !selectedRecord) {
        setSelectedRecord(records[0]);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const res = await verifyAuditChain();
      setVerifyResult(res);
    } finally {
      setVerifying(false);
    }
  };

  const getActionPill = (decision: string) => {
    switch (decision) {
      case "ALLOW":
        return "bg-[#064E3B]/40 text-[#34D399] border-[#065F46]";
      case "CONFIRM":
        return "bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]";
      case "REVISE":
        return "bg-[#7C2D12]/40 text-[#FB923C] border-[#9A3412]";
      case "BLOCK":
      default:
        return "bg-[#881337]/40 text-[#FB7185] border-[#9F1239]";
    }
  };

  let parsedPayload: any = {};
  if (selectedRecord) {
    try {
      parsedPayload = JSON.parse(selectedRecord.payload);
    } catch {
      parsedPayload = { raw: selectedRecord.payload };
    }
  }

  return (
    <div className="h-full flex flex-col gap-3 overflow-hidden">
      {/* 1. Header Bar */}
      <div className="flex-shrink-0 flex items-center justify-between gap-3 p-3 bg-[#18181B] border border-[#27272A] rounded-lg">
        <div>
          <h1 className="text-base font-bold text-[#FAFAFA] flex items-center gap-2">
            🛡️ Cryptographic Audit Ledger
          </h1>
          <p className="text-xs text-[#A1A1AA]">
            Tamper-evident log sealed with SHA-256 digital signatures.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchLogs}
            disabled={loading}
            className="text-sm font-medium text-[#A1A1AA] hover:text-[#FAFAFA] bg-[#121215] border border-[#27272A] px-3.5 py-1.5 rounded-md transition-colors"
          >
            Refresh
          </button>
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="text-sm font-bold bg-[#FAFAFA] hover:bg-white text-[#09090B] px-4 py-1.5 rounded-md transition-colors flex items-center gap-2 shadow-sm"
          >
            {verifying ? "Checking Chain..." : "🔐 Test Log Integrity"}
          </button>
        </div>
      </div>

      {/* Verification Result Notification */}
      {verifyResult && (
        <div
          className={`flex-shrink-0 p-3 rounded-lg border text-sm font-medium ${
            verifyResult.valid
              ? "bg-[#064E3B]/30 border-[#065F46] text-[#34D399]"
              : "bg-[#881337]/30 border-[#9F1239] text-[#FB7185]"
          }`}
        >
          {verifyResult.valid ? "✓ Audit Log Valid: Zero tampering detected across entire chain." : `✕ Tampering detected: ${verifyResult.reason}`}
        </div>
      )}

      {/* 2. Main Two-Column View-Fit Ledger Area */}
      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-3 overflow-hidden">
        {/* Left Column: Historical Records List */}
        <div className="lg:col-span-5 bg-[#18181B] border border-[#27272A] rounded-lg flex flex-col overflow-hidden">
          <div className="px-4 py-2.5 bg-[#121215] border-b border-[#27272A] text-xs font-bold text-[#A1A1AA] flex justify-between">
            <span>RECORDS ({logs.length})</span>
            <span>CLICK TO VIEW DETAILS</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-[#222226]">
            {loading ? (
              <div className="p-12 text-center text-sm text-[#71717A]">
                Loading records...
              </div>
            ) : logs.length === 0 ? (
              <div className="p-12 text-center text-sm text-[#71717A]">
                No logged decisions yet.
              </div>
            ) : (
              logs.map((record, idx) => {
                const isSelected = selectedRecord?.audit_id === record.audit_id;
                return (
                  <button
                    key={record.audit_id}
                    onClick={() => setSelectedRecord(record)}
                    className={`w-full text-left p-3.5 transition-colors flex flex-col gap-1.5 ${
                      isSelected ? "bg-[#27272A]/70 border-l-2 border-[#FAFAFA]" : "hover:bg-[#121215]/50"
                    }`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-[#71717A]">#{logs.length - idx}</span>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getActionPill(record.decision)}`}>
                          {record.decision}
                        </span>
                      </div>
                      <span className="text-xs text-[#71717A]">
                        {new Date(record.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <div className="text-xs font-mono text-[#E4E4E7] truncate w-full">
                      {record.audit_id}
                    </div>

                    <p className="text-xs text-[#A1A1AA] truncate w-full">
                      {record.rationale}
                    </p>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Selected Record Deep Dive (Fills height without page scroll) */}
        <div className="lg:col-span-7 bg-[#18181B] border border-[#27272A] rounded-lg flex flex-col overflow-hidden">
          <div className="px-4 py-2.5 bg-[#121215] border-b border-[#27272A] text-xs font-bold text-[#A1A1AA] flex justify-between">
            <span>SELECTED AUDIT BLOCK DETAILS</span>
            <span className="font-mono">{selectedRecord?.audit_id || "None Selected"}</span>
          </div>

          {selectedRecord ? (
            <div className="flex-1 overflow-y-auto p-4 space-y-3.5">
              {/* Verdict & Reason */}
              <div className="p-3 bg-[#121215] border border-[#27272A] rounded-md space-y-1">
                <div className="flex items-center justify-between">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded border ${getActionPill(selectedRecord.decision)}`}>
                    {selectedRecord.decision}
                  </span>
                  <span className="text-xs text-[#71717A]">
                    Timestamp: {new Date(selectedRecord.timestamp).toUTCString()}
                  </span>
                </div>
                <p className="text-sm text-[#FAFAFA] font-medium pt-1">
                  <strong>Rationale:</strong> {selectedRecord.rationale}
                </p>
              </div>

              {/* Hash Verification Lineage */}
              <div className="space-y-2 text-xs font-mono bg-[#09090B] p-3 rounded-md border border-[#222226]">
                <div>
                  <span className="text-[#71717A] text-[11px] block">Current Block Digital Signature (SHA-256)</span>
                  <span className="text-[#34D399] font-bold break-all text-xs">
                    {selectedRecord.current_hash}
                  </span>
                </div>
                <div className="pt-2 border-t border-[#18181B]">
                  <span className="text-[#71717A] text-[11px] block">Previous Block Signature (Cryptographic Link)</span>
                  <span className="text-[#A1A1AA] break-all text-xs">
                    {selectedRecord.prev_hash || "GENESIS ROOT"}
                  </span>
                </div>
              </div>

              {/* Payload JSON */}
              <div className="space-y-1">
                <span className="text-xs font-bold text-[#A1A1AA]">Original Evaluated Payload JSON</span>
                <div className="bg-[#09090B] rounded-md p-3 text-xs font-mono text-[#A1A1AA] border border-[#222226] max-h-[240px] overflow-y-auto">
                  <pre className="text-xs leading-relaxed">
                    {JSON.stringify(parsedPayload, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-sm text-[#71717A]">
              Select a record on the left to inspect its digital signatures and parameters.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
