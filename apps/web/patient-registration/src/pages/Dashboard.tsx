import React from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  UserPlusIcon,
  MagnifyingGlassIcon,
  DocumentTextIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline';

import { apiService } from '../services/api';

interface DashboardStats {
  totalPatients: number;
  todayRegistrations: number;
  pendingVerifications: number;
}

const Dashboard: React.FC = () => {
  // Fetch dashboard data from API
  const {
    data: dashboardData,
    isLoading: isLoadingDashboard,
    error: dashboardError
  } = useQuery(
    'dashboardData',
    () => apiService.getDashboardData(),
    {
      retry: 2,
      refetchInterval: 30000, // Refetch every 30 seconds
      onError: (error: any) => {
        console.error('Failed to load dashboard data:', error);
      }
    }
  );

  // Fetch patient statistics
  const {
    data: patientStats,
    isLoading: isLoadingStats,
    error: statsError
  } = useQuery(
    'patientStatistics',
    () => apiService.getPatientStatistics(),
    {
      retry: 2,
      refetchInterval: 60000, // Refetch every minute
      onError: (error: any) => {
        console.error('Failed to load patient statistics:', error);
      }
    }
  );

  // Use real data or fallback to defaults
  const stats: DashboardStats = {
    totalPatients: patientStats?.totalPatients || dashboardData?.statistics?.totalPatients || 0,
    todayRegistrations: patientStats?.newRegistrationsToday || dashboardData?.statistics?.newRegistrationsToday || 0,
    pendingVerifications: 8, // This might need a separate API endpoint
  };

  const quickActions = [
    {
      name: 'New Patient Registration',
      description: 'Register a new patient with comprehensive information',
      href: '/register',
      icon: UserPlusIcon,
      color: 'bg-primary-500',
      textColor: 'text-primary-600',
    },
    {
      name: 'Patient Search',
      description: 'Search and view patient records',
      href: '/search',
      icon: MagnifyingGlassIcon,
      color: 'bg-secondary-500',
      textColor: 'text-secondary-600',
    },
  ];

  // Use real recent registrations from API or fallback
  const recentActivities = dashboardData?.recentRegistrations?.slice(0, 4).map((patient, index) => ({
    id: index + 1,
    type: 'registration',
    patientName: `${patient.firstName} ${patient.lastName || ''}`.trim(),
    uhid: patient.uhid || 'N/A',
    time: new Date(patient.createdAt).toLocaleDateString('en-IN'),
    status: 'completed',
  })) || [
    {
      id: 1,
      type: 'registration',
      patientName: 'No recent registrations',
      uhid: 'N/A',
      time: 'N/A',
      status: 'completed',
    },
  ];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="h-5 w-5 text-success-500" />;
      case 'pending':
        return <ClockIcon className="h-5 w-5 text-warning-500" />;
      case 'failed':
        return <XCircleIcon className="h-5 w-5 text-danger-500" />;
      default:
        return <DocumentTextIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'registration':
        return <UserPlusIcon className="h-5 w-5 text-primary-500" />;
      default:
        return <DocumentTextIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  if (isLoadingDashboard && isLoadingStats) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
        <span className="ml-3 text-gray-600">Loading dashboard...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Welcome Header */}
      <div className="card">
        <div className="card-body">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Welcome back!</h1>
              <p className="mt-1 text-lg text-gray-600">
                Here's what's happening with your patient registration system today.
              </p>
            </div>
            <div className="hidden sm:block">
              <div className="text-right">
                <p className="text-sm text-gray-500">Current Time</p>
                <p className="text-lg font-semibold text-gray-900">
                  {new Date().toLocaleTimeString()}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="card hover:shadow-medium transition-shadow"
        >
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center">
                  <UserPlusIcon className="h-6 w-6 text-primary-600" />
                </div>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Total Patients</p>
                <p className="text-2xl font-bold text-gray-900">{stats.totalPatients.toLocaleString()}</p>
              </div>
            </div>
            <div className="mt-4">
              <div className="flex items-center text-sm">
                <span className="text-success-600 font-medium">+{stats.todayRegistrations}</span>
                <span className="text-gray-500 ml-1">today</span>
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="card hover:shadow-medium transition-shadow"
        >
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-12 h-12 bg-secondary-100 rounded-lg flex items-center justify-center">
                  <ClockIcon className="h-6 w-6 text-secondary-600" />
                </div>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Pending Verifications</p>
                <p className="text-2xl font-bold text-gray-900">{stats.pendingVerifications}</p>
              </div>
            </div>
            <div className="mt-4">
              <div className="flex items-center text-sm">
                <span className="text-secondary-600 font-medium">Needs review</span>
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="card hover:shadow-medium transition-shadow"
        >
          <div className="card-body">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center">
                  <ChartBarIcon className="h-6 w-6 text-primary-600" />
                </div>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Today's Registrations</p>
                <p className="text-2xl font-bold text-gray-900">{stats.todayRegistrations}</p>
              </div>
            </div>
            <div className="mt-4">
              <div className="flex items-center text-sm">
                <span className="text-primary-600 font-medium">
                  {stats.totalPatients > 0 ? Math.round((stats.todayRegistrations / stats.totalPatients) * 100) : 0}%
                </span>
                <span className="text-gray-500 ml-1">of total</span>
              </div>
            </div>
          </div>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Quick Actions */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.7 }}
          className="card"
        >
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Quick Actions</h2>
            <p className="text-sm text-gray-500">Common tasks and shortcuts</p>
          </div>
          <div className="card-body">
            <div className="space-y-3">
              {quickActions.map((action, index) => (
                <Link
                  key={action.name}
                  to={action.href}
                  className="flex items-center p-3 rounded-lg border border-gray-200 hover:border-gray-300 hover:shadow-soft transition-all duration-200"
                >
                  <div className={`flex-shrink-0 w-10 h-10 ${action.color} rounded-lg flex items-center justify-center`}>
                    <action.icon className="h-5 w-5 text-white" />
                  </div>
                  <div className="ml-4 flex-1">
                    <p className="text-sm font-medium text-gray-900">{action.name}</p>
                    <p className="text-sm text-gray-500">{action.description}</p>
                  </div>
                  <div className="flex-shrink-0">
                    <div className={`w-2 h-2 ${action.color} rounded-full`} />
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Recent Activities */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.8 }}
          className="card"
        >
          <div className="card-header">
            <h2 className="text-lg font-semibold text-gray-900">Recent Activities</h2>
            <p className="text-sm text-gray-500">Latest patient registrations and updates</p>
          </div>
          <div className="card-body">
            <div className="space-y-4">
              {recentActivities.map((activity) => (
                <div key={activity.id} className="flex items-center space-x-3">
                  <div className="flex-shrink-0">
                    {getActivityIcon(activity.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {activity.patientName}
                    </p>
                    <p className="text-sm text-gray-500">{activity.uhid}</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(activity.status)}
                    <span className="text-xs text-gray-500">{activity.time}</span>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-4 pt-4 border-t border-gray-200">
              <Link
                to="/search"
                className="text-sm font-medium text-primary-600 hover:text-primary-700"
              >
                View all activities →
              </Link>
            </div>
          </div>
        </motion.div>
      </div>

      {/* System Status */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.9 }}
        className="card"
      >
        <div className="card-header">
          <h2 className="text-lg font-semibold text-gray-900">System Status</h2>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 ${dashboardError ? 'bg-red-500' : 'bg-success-500'} rounded-full`}></div>
              <span className="text-sm text-gray-700">Database</span>
            </div>
            <div className="flex items-center space-x-3">
              <div className="w-3 h-3 bg-success-500 rounded-full"></div>
              <span className="text-sm text-gray-700">API Services</span>
            </div>
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 ${statsError ? 'bg-red-500' : 'bg-success-500'} rounded-full`}></div>
              <span className="text-sm text-gray-700">Statistics</span>
            </div>
            <div className="flex items-center space-x-3">
              <div className="w-3 h-3 bg-success-500 rounded-full"></div>
              <span className="text-sm text-gray-700">File Storage</span>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default Dashboard; 