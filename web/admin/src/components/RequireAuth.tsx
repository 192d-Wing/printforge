import { Navigate, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';
import { getToken } from '../lib/auth';

/// Wrap a route element with this to gate it behind a non-empty JWT.
/// The gateway is the real authority — this guard is about UX (don't
/// render a broken dashboard when there's no token), not security.
export default function RequireAuth({ children }: { children: ReactNode }) {
  const location = useLocation();
  if (!getToken()) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return <>{children}</>;
}
