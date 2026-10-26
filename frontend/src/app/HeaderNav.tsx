"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import React from "react";

export default function HeaderNav() {
  const pathname = usePathname();

  const navItems = [
    {
      href: "/",
      label: "Risk Interceptor",
      icon: "⚡",
    },
    {
      href: "/metrics",
      label: "Model Benchmarks",
      icon: "📊",
    },
    {
      href: "/audit",
      label: "Audit Ledger",
      icon: "🛡️",
    },
    {
      href: "/keys",
      label: "API Keys",
      icon: "🔑",
    },
    {
      href: "/auth",
      label: "Account",
      icon: "👤",
    },
  ];

  return (
    <header className="h-14 border-b border-[#27272A] bg-[#121215] flex-shrink-0 z-50">
      <div className="h-full max-w-[1600px] mx-auto px-4 sm:px-6 flex items-center justify-between">
        {/* Brand */}
        <Link href="/" className="flex items-center space-x-3 group">
          <div className="w-8 h-8 rounded bg-[#18181B] border border-[#27272A] flex items-center justify-center text-sm font-bold text-[#FAFAFA]">
            🛡️
          </div>
          <div className="flex items-center gap-2.5">
            <span className="font-bold text-base text-[#FAFAFA] tracking-tight">
              AI Risk Guard
            </span>
            <span className="text-xs font-mono font-medium text-[#34D399] bg-[#064E3B]/30 border border-[#065F46] px-2 py-0.5 rounded">
              Active Firewall
            </span>
          </div>
        </Link>

        {/* Larger Nav Tabs */}
        <nav className="flex items-center space-x-2">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`px-3.5 py-1.5 rounded-md text-sm font-medium transition-all flex items-center gap-2 ${
                  isActive
                    ? "bg-[#27272A] text-[#FAFAFA] border border-[#3F3F46] shadow-sm font-semibold"
                    : "text-[#A1A1AA] hover:text-[#FAFAFA] hover:bg-[#18181B] border border-transparent"
                }`}
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
