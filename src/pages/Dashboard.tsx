import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  CardHeader,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  LinearProgress,
  Button
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon
} from '@mui/icons-material';
import apiService from '../services/api';

// Define the Scan type
interface Scan {
  id: string;
  name: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  startTime: string;
  endTime?: string;
}

// Define the Summary type
interface Summary {
  totalScans: number;
  activeScans: number;
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
  infoVulnerabilities: number;
}

const Dashboard: React.FC = () => {
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [summary, setSummary] = useState<Summary>({
    totalScans: 0,
    activeScans: 0,
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
    highVulnerabilities: 0,
    mediumVulnerabilities: 0,
    lowVulnerabilities: 0,
    infoVulnerabilities: 0,
  });
  const [loading, setLoading] = useState(true);

  // Fetch dashboard data
  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        // In a real application, these would be actual API calls
        // For now, we'll simulate the data

        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Mock data
        const mockSummary: Summary = {
          totalScans: 24,
          activeScans: 3,
          totalVulnerabilities: 156,
          criticalVulnerabilities: 12,
          highVulnerabilities: 28,
          mediumVulnerabilities: 45,
          lowVulnerabilities: 61,
          infoVulnerabilities: 10,
        };

        const mockScans: Scan[] = [
          {
            id: '1',
            name: 'Weekly Web Server Scan',
            target: 'web-server-01.example.com',
            status: 'completed',
            vulnerabilities: {
              critical: 2,
              high: 5,
              medium: 8,
              low: 12,
              info: 3,
            },
            startTime: '2023-06-15T08:30:00Z',
            endTime: '2023-06-15T09:45:00Z',
          },
          {
            id: '2',
            name: 'Database Server Scan',
            target: 'db-server-01.example.com',
            status: 'running',
            vulnerabilities: {
              critical: 1,
              high: 3,
              medium: 5,
              low: 7,
              info: 2,
            },
            startTime: '2023-06-16T10:15:00Z',
          },
          {
            id: '3',
            name: 'API Gateway Scan',
            target: 'api-gateway.example.com',
            status: 'pending',
            vulnerabilities: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0,
            },
            startTime: '2023-06-16T14:00:00Z',
          },
          {
            id: '4',
            name: 'Authentication Service Scan',
            target: 'auth-service.example.com',
            status: 'completed',
            vulnerabilities: {
              critical: 0,
              high: 2,
              medium: 4,
              low: 6,
              info: 1,
            },
            startTime: '2023-06-14T09:00:00Z',
            endTime: '2023-06-14T10:30:00Z',
          },
          {
            id: '5',
            name: 'Payment Gateway Scan',
            target: 'payment.example.com',
            status: 'failed',
            vulnerabilities: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0,
            },
            startTime: '2023-06-13T11:00:00Z',
            endTime: '2023-06-13T11:15:00Z',
          },
        ];

        setSummary(mockSummary);
        setRecentScans(mockScans);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, []);

  // Get status chip color
  const getStatusChip = (status: string) => {
    switch (status) {
      case 'completed':
        return <Chip label="Completed" color="success" size="small" icon={<CheckCircleIcon />} />;
      case 'running':
        return <Chip label="Running" color="primary" size="small" />;
      case 'pending':
        return <Chip label="Pending" color="default" size="small" />;
      case 'failed':
        return <Chip label="Failed" color="error" size="small" icon={<ErrorIcon />} />;
      default:
        return <Chip label={status} color="default" size="small" />;
    }
  };

  // Format date
  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  // Calculate total vulnerabilities for a scan
  const getTotalVulnerabilities = (scan: Scan) => {
    return (
      scan.vulnerabilities.critical +
      scan.vulnerabilities.high +
      scan.vulnerabilities.medium +
      scan.vulnerabilities.low +
      scan.vulnerabilities.info
    );
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>

      {loading ? (
        <LinearProgress />
      ) : (
        <>
          {/* Summary Cards */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Total Scans
                  </Typography>
                  <Typography variant="h3">{summary.totalScans}</Typography>
                  <Typography variant="body2" color="textSecondary">
                    {summary.activeScans} active
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Critical Vulnerabilities
                  </Typography>
                  <Typography variant="h3" color="error">
                    {summary.criticalVulnerabilities}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Require immediate attention
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    High Vulnerabilities
                  </Typography>
                  <Typography variant="h3" color="warning.main">
                    {summary.highVulnerabilities}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Require prompt attention
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Total Vulnerabilities
                  </Typography>
                  <Typography variant="h3">
                    {summary.totalVulnerabilities}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Across all scans
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Recent Scans */}
          <Paper sx={{ p: 2, mb: 4 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Recent Scans</Typography>
              <Button variant="outlined" size="small">
                View All
              </Button>
            </Box>

            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Target</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Vulnerabilities</TableCell>
                    <TableCell>Start Time</TableCell>
                    <TableCell>End Time</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {recentScans.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell>{scan.name}</TableCell>
                      <TableCell>{scan.target}</TableCell>
                      <TableCell>{getStatusChip(scan.status)}</TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', gap: 0.5 }}>
                          {scan.vulnerabilities.critical > 0 && (
                            <Chip
                              label={`${scan.vulnerabilities.critical} Critical`}
                              size="small"
                              color="error"
                              variant="outlined"
                            />
                          )}
                          {scan.vulnerabilities.high > 0 && (
                            <Chip
                              label={`${scan.vulnerabilities.high} High`}
                              size="small"
                              color="warning"
                              variant="outlined"
                            />
                          )}
                          {getTotalVulnerabilities(scan) >
                            (scan.vulnerabilities.critical + scan.vulnerabilities.high) && (
                            <Chip
                              label={`+${getTotalVulnerabilities(scan) -
                                (scan.vulnerabilities.critical + scan.vulnerabilities.high)} More`}
                              size="small"
                              variant="outlined"
                            />
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>{formatDate(scan.startTime)}</TableCell>
                      <TableCell>{formatDate(scan.endTime)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Vulnerability Distribution */}
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Vulnerability Distribution
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      By Severity
                    </Typography>

                    <Box sx={{ mt: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <Box sx={{ width: '100px' }}>
                          <Typography variant="body2">Critical</Typography>
                        </Box>
                        <Box sx={{ flexGrow: 1, mr: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={(summary.criticalVulnerabilities / summary.totalVulnerabilities) * 100}
                            color="error"
                            sx={{ height: 10, borderRadius: 5 }}
                          />
                        </Box>
                        <Typography variant="body2">{summary.criticalVulnerabilities}</Typography>
                      </Box>

                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <Box sx={{ width: '100px' }}>
                          <Typography variant="body2">High</Typography>
                        </Box>
                        <Box sx={{ flexGrow: 1, mr: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={(summary.highVulnerabilities / summary.totalVulnerabilities) * 100}
                            color="warning"
                            sx={{ height: 10, borderRadius: 5 }}
                          />
                        </Box>
                        <Typography variant="body2">{summary.highVulnerabilities}</Typography>
                      </Box>

                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <Box sx={{ width: '100px' }}>
                          <Typography variant="body2">Medium</Typography>
                        </Box>
                        <Box sx={{ flexGrow: 1, mr: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={(summary.mediumVulnerabilities / summary.totalVulnerabilities) * 100}
                            color="info"
                            sx={{ height: 10, borderRadius: 5 }}
                          />
                        </Box>
                        <Typography variant="body2">{summary.mediumVulnerabilities}</Typography>
                      </Box>

                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <Box sx={{ width: '100px' }}>
                          <Typography variant="body2">Low</Typography>
                        </Box>
                        <Box sx={{ flexGrow: 1, mr: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={(summary.lowVulnerabilities / summary.totalVulnerabilities) * 100}
                            color="success"
                            sx={{ height: 10, borderRadius: 5 }}
                          />
                        </Box>
                        <Typography variant="body2">{summary.lowVulnerabilities}</Typography>
                      </Box>

                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <Box sx={{ width: '100px' }}>
                          <Typography variant="body2">Info</Typography>
                        </Box>
                        <Box sx={{ flexGrow: 1, mr: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={(summary.infoVulnerabilities / summary.totalVulnerabilities) * 100}
                            color="primary"
                            sx={{ height: 10, borderRadius: 5 }}
                          />
                        </Box>
                        <Typography variant="body2">{summary.infoVulnerabilities}</Typography>
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} md={6}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      Quick Actions
                    </Typography>

                    <Box sx={{ mt: 2 }}>
                      <Button variant="contained" fullWidth sx={{ mb: 2 }}>
                        Start New Scan
                      </Button>

                      <Button variant="outlined" fullWidth sx={{ mb: 2 }}>
                        View Vulnerabilities
                      </Button>

                      <Button variant="outlined" fullWidth>
                        Generate Report
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Paper>
        </>
      )}
    </Box>
  );
};

export default Dashboard;
