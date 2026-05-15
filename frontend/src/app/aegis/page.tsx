'use client';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function AegisPage() {
  const router = useRouter();
  useEffect(() => { router.replace('/copilot'); }, [router]);
  return null;
}
