"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth-context";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard", icon: "◈" },
  { href: "/servers", label: "Servers", icon: "▤" },
  { href: "/findings", label: "Findings", icon: "▲" },
  { href: "/reports", label: "Reports", icon: "▦" },
  { href: "/settings", label: "Settings", icon: "⚙" },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  return (
    <aside className="flex h-screen w-60 flex-none flex-col border-r border-base-600 bg-base-900">
      <div className="flex items-center gap-2 px-5 py-5">
        <span className="font-mono text-lg font-bold text-signal-500">SG</span>
        <span className="font-sans text-sm font-semibold tracking-wide text-ink-100">
          SentinelGuard
        </span>
      </div>

      <nav className="flex-1 space-y-1 px-3">
        {NAV_ITEMS.map((item) => {
          const active = pathname?.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                active
                  ? "bg-base-700 text-ink-100"
                  : "text-ink-500 hover:bg-base-800 hover:text-ink-300"
              }`}
            >
              <span className="font-mono text-xs">{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-base-600 px-4 py-4">
        <p className="truncate text-xs text-ink-500">{user?.email}</p>
        <p className="mb-3 text-[10px] uppercase tracking-wide text-ink-700">{user?.role}</p>
        <button
          onClick={logout}
          className="w-full rounded-md border border-base-600 px-3 py-1.5 text-xs text-ink-300 transition-colors hover:border-signal-600 hover:text-signal-400"
        >
          Sign out
        </button>
      </div>
    </aside>
  );
}
