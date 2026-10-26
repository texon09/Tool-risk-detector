"use client";

import React, { useEffect, useState } from "react";
import { getCurrentUser, login, signup, setStoredSessionToken, User } from "@/lib/api";

export default function AuthPage() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    getCurrentUser().then((user) => setCurrentUser(user));
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setMessage(null);
    setLoading(true);

    try {
      if (isLogin) {
        const res = await login(email, password);
        setCurrentUser(res.user);
        setMessage("Logged in successfully! You can now generate API keys and view your personal audit trail.");
      } else {
        const res = await signup(email, password);
        setCurrentUser(res.user);
        setMessage("Account created successfully! Session token stored.");
      }
    } catch (err: any) {
      setError(err.message || "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setStoredSessionToken(null);
    setCurrentUser(null);
    setMessage("Logged out successfully.");
  };

  return (
    <div className="max-w-md mx-auto mt-8 p-6 bg-[#18181B] border border-[#27272A] rounded-xl shadow-lg text-[#FAFAFA]">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-[#27272A] flex items-center justify-center text-xl">
          👤
        </div>
        <div>
          <h1 className="text-lg font-bold">PlanGuard Account</h1>
          <p className="text-xs text-[#A1A1AA]">Manage API keys & audit ledger identity</p>
        </div>
      </div>

      {currentUser ? (
        <div className="space-y-4">
          <div className="p-4 bg-[#121215] border border-[#27272A] rounded-lg">
            <span className="text-xs text-[#A1A1AA]">Signed in as:</span>
            <p className="font-semibold text-sm text-[#38BDF8] mt-1">{currentUser.email}</p>
            <span className="text-xs text-[#71717A]">User ID: {currentUser.id}</span>
          </div>

          <div className="flex gap-3">
            <a
              href="/keys"
              className="flex-1 text-center py-2 px-4 rounded-md text-xs font-semibold bg-[#27272A] hover:bg-[#3F3F46] transition-colors"
            >
              🔑 Manage API Keys
            </a>
            <a
              href="/audit"
              className="flex-1 text-center py-2 px-4 rounded-md text-xs font-semibold bg-[#27272A] hover:bg-[#3F3F46] transition-colors"
            >
              🛡️ View My Audits
            </a>
          </div>

          <button
            onClick={handleLogout}
            className="w-full py-2 px-4 rounded-md text-xs font-semibold bg-[#7F1D1D]/30 border border-[#991B1B] text-[#FCA5A5] hover:bg-[#991B1B]/40 transition-colors"
          >
            Log Out
          </button>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex border-b border-[#27272A] pb-2 mb-4">
            <button
              type="button"
              onClick={() => { setIsLogin(true); setError(null); }}
              className={`flex-1 py-1 text-sm font-semibold transition-colors ${
                isLogin ? "text-[#FAFAFA] border-b-2 border-[#38BDF8]" : "text-[#71717A] hover:text-[#A1A1AA]"
              }`}
            >
              Log In
            </button>
            <button
              type="button"
              onClick={() => { setIsLogin(false); setError(null); }}
              className={`flex-1 py-1 text-sm font-semibold transition-colors ${
                !isLogin ? "text-[#FAFAFA] border-b-2 border-[#38BDF8]" : "text-[#71717A] hover:text-[#A1A1AA]"
              }`}
            >
              Sign Up
            </button>
          </div>

          {error && (
            <div className="p-3 bg-[#7F1D1D]/30 border border-[#991B1B] text-[#FCA5A5] text-xs rounded-lg">
              {error}
            </div>
          )}

          {message && (
            <div className="p-3 bg-[#064E3B]/30 border border-[#065F46] text-[#34D399] text-xs rounded-lg">
              {message}
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-[#A1A1AA] mb-1">Email Address</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="agent@example.com"
              className="w-full px-3 py-2 bg-[#121215] border border-[#27272A] rounded-lg text-sm text-[#FAFAFA] focus:outline-none focus:border-[#38BDF8]"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[#A1A1AA] mb-1">Password</label>
            <input
              type="password"
              required
              minLength={6}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3 py-2 bg-[#121215] border border-[#27272A] rounded-lg text-sm text-[#FAFAFA] focus:outline-none focus:border-[#38BDF8]"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-lg text-sm font-bold bg-[#FAFAFA] text-[#09090B] hover:bg-white transition-colors shadow-sm disabled:opacity-50"
          >
            {loading ? "Processing..." : isLogin ? "Sign In" : "Create Account"}
          </button>
        </form>
      )}
    </div>
  );
}
