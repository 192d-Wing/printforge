import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import RequireAuth from './components/RequireAuth';
import Alerts from './pages/Alerts';
import Dashboard from './pages/Dashboard';
import Fleet from './pages/Fleet';
import Jobs from './pages/Jobs';
import Login from './pages/Login';
import ReportDetail from './pages/ReportDetail';
import Reports from './pages/Reports';
import UserDetail from './pages/UserDetail';
import Users from './pages/Users';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      retry: (failureCount, err: unknown) => {
        // A 401 means our token is stale — don't keep retrying; let
        // RequireAuth bounce the user back to /login on the next render.
        const status = (err as { status?: number } | null)?.status;
        if (status === 401 || status === 403) return false;
        return failureCount < 2;
      },
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="fleet" element={<Fleet />} />
            <Route path="jobs" element={<Jobs />} />
            <Route path="users" element={<Users />} />
            <Route path="users/:edipi" element={<UserDetail />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="reports" element={<Reports />} />
            <Route path="reports/:id" element={<ReportDetail />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
