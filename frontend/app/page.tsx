"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { LoadingState } from "@/components/Layout";

export default function RootPage() {
  const { token, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (isLoading) return;
    router.push(token ? "/dashboard" : "/login");
  }, [isLoading, token, router]);

  return (
    <div className="flex h-screen items-center justify-center bg-base-950">
      <LoadingState />
    </div>
  );
}
