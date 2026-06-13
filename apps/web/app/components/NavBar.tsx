"use client";

import { Activity, LayoutDashboard, Search, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Command Center", icon: LayoutDashboard },
  { href: "/developer-surface", label: "Developer Surface", icon: Search },
];

export function NavBar() {
  const pathname = usePathname();
  return (
    <aside className="nav">
      <div className="brand">
        <ShieldCheck size={16} style={{ display: "inline", marginRight: 6, verticalAlign: "middle" }} />
        RedCalibur 2.0
      </div>
      {NAV_ITEMS.map(({ href, label, icon: Icon }) => (
        <Link
          key={href}
          href={href}
          className={`nav-item${pathname === href ? " nav-item--active" : ""}`}
        >
          <Icon size={15} />
          {label}
        </Link>
      ))}
    </aside>
  );
}
