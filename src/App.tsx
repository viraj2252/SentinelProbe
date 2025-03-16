import { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, CssBaseline } from '@mui/material';
import theme from './utils/theme';
import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/Auth/ProtectedRoute';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <Router>
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<Login />} />

            {/* Protected routes */}
            <Route element={<ProtectedRoute />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scans" element={<div>Scans Page</div>} />
              <Route path="/vulnerabilities" element={<div>Vulnerabilities Page</div>} />
              <Route path="/reports" element={<div>Reports Page</div>} />
              <Route path="/tests" element={<div>Security Tests Page</div>} />
              <Route path="/settings" element={<div>Settings Page</div>} />
            </Route>

            {/* Redirect to dashboard for any unknown routes */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
