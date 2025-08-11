import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { QueryClient, QueryClientProvider } from 'react-query';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import PatientRegistration from './pages/PatientRegistration';
import PatientSearch from './pages/PatientSearch';
import PatientDetails from './pages/PatientDetails';
import Settings from './pages/Settings';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <div className="min-h-screen bg-gray-50">
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/register" element={<PatientRegistration />} />
            <Route path="/search" element={<PatientSearch />} />
            <Route path="/patient/:id" element={<PatientDetails />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </Layout>
        
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#363636',
              color: '#fff',
            },
            success: {
              duration: 3000,
              iconTheme: {
                primary: '#22c55e',
                secondary: '#fff',
              },
            },
            error: {
              duration: 5000,
              iconTheme: {
                primary: '#ef4444',
                secondary: '#fff',
              },
            },
          }}
        />
      </div>
    </QueryClientProvider>
  );
}

export default App; 