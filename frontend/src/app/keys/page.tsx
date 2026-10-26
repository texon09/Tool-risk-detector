"use client";

import React, { useEffect, useState } from "react";
import {
  ApiKey,
  createApiKey,
  getCurrentUser,
  listApiKeys,
  revokeApiKey,
  User,
} from "@/lib/api";

export default function ApiKeysPage() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [label, setLabel] = useState("");
  const [creating, setCreating] = useState(false);
  const [newKeySecret, setNewKeySecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const user = await getCurrentUser();
      setCurrentUser(user);
      if (user) {
        const keyList = await listApiKeys();
        setKeys(keyList);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!label.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const res = await createApiKey(label.trim());
      setNewKeySecret(res.api_key);
      setLabel("");
      const keyList = await listApiKeys();
      setKeys(keyList);
    } catch (err: any) {
      setError(err.message || "Failed to create API key");
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (keyId: string) => {
    if (!confirm("Are you sure you want to revoke this API key? Agents using it will fail closed.")) {
      return;
    }
    const ok = await revokeApiKey(keyId);
    if (ok) {
      const keyList = await listApiKeys();
      setKeys(keyList);
    }
  };

  const copyToClipboard = () => {
    if (newKeySecret) {
      navigator.clipboard.writeText(newKeySecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (loading) {
    return (
      <div className="max-w-3xl mx-auto mt-12 p-6 text-center text-[#A1A1AA]">
        Loading API keys...
      </div>
    );
  }

  if (!currentUser) {
    return (
      <div className="max-w-md mx-auto mt-12 p-6 bg-[#18181B] border border-[#27272A] rounded-xl text-center">
        <h2 className="text-base font-bold text-[#FAFAFA] mb-2">Authentication Required</h2>
        <p className="text-xs text-[#A1A1AA] mb-4">
          Please sign in to generate API keys and link autonomous agents to your audit ledger.
        </p>
        <a
          href="/auth"
          className="inline-block px-4 py-2 bg-[#FAFAFA] text-[#09090B] font-bold text-xs rounded-md shadow-sm hover:bg-white"
        >
          Sign In / Sign Up
        </a>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto mt-6 space-y-6 text-[#FAFAFA]">
      {/* Header */}
      <div className="flex items-center justify-between p-4 bg-[#18181B] border border-[#27272A] rounded-xl">
        <div>
          <h1 className="text-base font-bold flex items-center gap-2">
            🔑 PlanGuard API Keys
          </h1>
          <p className="text-xs text-[#A1A1AA]">
            Authenticate your agent or chat demo requests with the <code className="text-[#38BDF8]">X-API-Key</code> header to bind executions to your audit ledger.
          </p>
        </div>
        <span className="text-xs text-[#34D399] bg-[#064E3B]/30 border border-[#065F46] px-2.5 py-1 rounded-full font-mono">
          {currentUser.email}
        </span>
      </div>

      {/* Secret Key Display Modal / Banner (shown once) */}
      {newKeySecret && (
        <div className="p-4 bg-[#064E3B]/20 border border-[#065F46] rounded-xl space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#34D399] flex items-center gap-1.5">
              ⚠️ Save Your API Key Now
            </span>
            <button
              onClick={() => setNewKeySecret(null)}
              className="text-xs text-[#A1A1AA] hover:text-[#FAFAFA]"
            >
              Dismiss
            </button>
          </div>
          <p className="text-xs text-[#D1D5DB]">
            This secret key will <strong>never be shown again</strong>. Add it to your agent’s <code className="text-[#FBBF24]">.env</code> as <code className="text-[#FBBF24]">PLANGUARD_API_KEY</code>.
          </p>
          <div className="flex items-center gap-2">
            <input
              type="text"
              readOnly
              value={newKeySecret}
              className="flex-1 font-mono text-xs px-3 py-2 bg-[#121215] border border-[#27272A] rounded-lg text-[#34D399]"
            />
            <button
              onClick={copyToClipboard}
              className="px-3 py-2 bg-[#FAFAFA] text-[#09090B] font-bold text-xs rounded-lg hover:bg-white transition-colors"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
        </div>
      )}

      {/* Create Key Form */}
      <form onSubmit={handleCreate} className="p-4 bg-[#18181B] border border-[#27272A] rounded-xl flex gap-3">
        <input
          type="text"
          required
          placeholder="Key label (e.g. Chat Demo, LangChain Bot, CLI)"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          className="flex-1 px-3 py-2 bg-[#121215] border border-[#27272A] rounded-lg text-sm text-[#FAFAFA] focus:outline-none focus:border-[#38BDF8]"
        />
        <button
          type="submit"
          disabled={creating}
          className="px-4 py-2 bg-[#FAFAFA] text-[#09090B] font-bold text-xs rounded-lg hover:bg-white transition-colors shadow-sm disabled:opacity-50"
        >
          {creating ? "Generating..." : "Generate New Key"}
        </button>
      </form>

      {error && (
        <div className="p-3 bg-[#7F1D1D]/30 border border-[#991B1B] text-[#FCA5A5] text-xs rounded-lg">
          {error}
        </div>
      )}

      {/* Keys Table */}
      <div className="bg-[#18181B] border border-[#27272A] rounded-xl overflow-hidden">
        <div className="p-3 border-b border-[#27272A] flex justify-between items-center text-xs font-semibold text-[#A1A1AA]">
          <span>Active & Revoked Keys ({keys.length})</span>
        </div>
        {keys.length === 0 ? (
          <div className="p-8 text-center text-xs text-[#71717A]">
            No API keys created yet. Generate one above to use with PlanGuard.
          </div>
        ) : (
          <div className="divide-y divide-[#27272A]">
            {keys.map((k) => (
              <div key={k.id} className="p-3 flex items-center justify-between text-xs">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-[#FAFAFA]">{k.label}</span>
                    <span className="font-mono text-[#A1A1AA] bg-[#121215] px-1.5 py-0.5 rounded border border-[#27272A]">
                      {k.key_prefix}
                    </span>
                    {k.revoked ? (
                      <span className="text-[10px] font-semibold text-[#FB7185] bg-[#881337]/30 border border-[#9F1239] px-1.5 py-0.5 rounded">
                        REVOKED
                      </span>
                    ) : (
                      <span className="text-[10px] font-semibold text-[#34D399] bg-[#064E3B]/30 border border-[#065F46] px-1.5 py-0.5 rounded">
                        ACTIVE
                      </span>
                    )}
                  </div>
                  <p className="text-[10px] text-[#71717A]">
                    Created: {new Date(k.created_at).toLocaleString()}
                  </p>
                </div>
                {!k.revoked && (
                  <button
                    onClick={() => handleRevoke(k.id)}
                    className="px-2.5 py-1 text-[11px] font-medium text-[#FB7185] hover:bg-[#881337]/30 border border-[#9F1239] rounded transition-colors"
                  >
                    Revoke
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
