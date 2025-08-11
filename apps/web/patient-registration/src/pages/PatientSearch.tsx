import React, { useState, useEffect } from 'react';
import { useQuery } from 'react-query';
import { Link } from 'react-router-dom';
import { MagnifyingGlassIcon, EyeIcon, PencilIcon, TrashIcon } from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import apiService from '@/services/api';
import { Patient, PatientSearchCriteria } from '@/types/patient';

const PatientSearch: React.FC = () => {
  const [searchCriteria, setSearchCriteria] = useState<PatientSearchCriteria>({
    firstName: '',
    lastName: '',
    mobileNumber: '',
    aadhaarNumber: '',
    uhid: '',
    dateOfBirth: '',
    gender: '',
    bloodGroup: '',
    registrationType: '',
    registrationSource: '',
    state: '',
    district: '',
    city: '',
    pinCode: ''
  });

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [isSearching, setIsSearching] = useState(false);

  // Search patients query
  const {
    data: searchResult,
    isLoading,
    error,
    refetch
  } = useQuery(
    ['patients', searchCriteria, currentPage, pageSize],
    () => apiService.searchPatients({
      ...searchCriteria,
      page: currentPage,
      limit: pageSize
    }),
    {
      enabled: false, // Don't auto-fetch, only fetch on search
      retry: 1,
      onError: (error: any) => {
        console.error('Search error:', error);
        toast.error('Failed to search patients. Please try again.');
      }
    }
  );

  // Get all patients for initial load
  const {
    data: allPatients,
    isLoading: isLoadingAll
  } = useQuery(
    ['allPatients', currentPage, pageSize],
    () => apiService.searchPatients({
      page: currentPage,
      limit: pageSize
    }),
    {
      retry: 1,
      onError: (error: any) => {
        console.error('Failed to load patients:', error);
        toast.error('Failed to load patients. Please try again.');
      }
    }
  );

  const handleSearch = async () => {
    setIsSearching(true);
    setCurrentPage(1);
    try {
      await refetch();
    } finally {
      setIsSearching(false);
    }
  };

  const handleClearSearch = () => {
    setSearchCriteria({
      firstName: '',
      lastName: '',
      mobileNumber: '',
      aadhaarNumber: '',
      uhid: '',
      dateOfBirth: '',
      gender: '',
      bloodGroup: '',
      registrationType: '',
      registrationSource: '',
      state: '',
      district: '',
      city: '',
      pinCode: ''
    });
    setCurrentPage(1);
  };

  const handleInputChange = (field: keyof PatientSearchCriteria, value: string) => {
    setSearchCriteria(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const patients = searchResult?.patients || allPatients?.patients || [];
  const totalPatients = searchResult?.total || allPatients?.total || 0;
  const totalPages = Math.ceil(totalPatients / pageSize);

  const formatDate = (dateString: string | undefined) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-IN');
  };

  const getGenderDisplay = (gender: string | undefined) => {
    if (!gender || gender.trim() === '') return 'N/A';
    return gender.charAt(0).toUpperCase() + gender.slice(1);
  };

  const getRegistrationTypeDisplay = (type: string | undefined) => {
    if (!type || type.trim() === '') return 'N/A';
    return type.charAt(0).toUpperCase() + type.slice(1);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Patient Search</h1>
          <p className="mt-1 text-gray-600">
            Search and manage patient records
          </p>
        </div>
        <Link
          to="/register"
          className="btn btn-primary"
        >
          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
          </svg>
          New Patient
        </Link>
      </div>

      {/* Search Form */}
      <div className="card">
        <div className="card-header">
          <h2 className="text-lg font-semibold text-gray-900">Search Criteria</h2>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Basic Information */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                First Name
              </label>
              <input
                type="text"
                value={searchCriteria.firstName}
                onChange={(e) => handleInputChange('firstName', e.target.value)}
                className="form-input w-full"
                placeholder="Enter first name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Last Name
              </label>
              <input
                type="text"
                value={searchCriteria.lastName}
                onChange={(e) => handleInputChange('lastName', e.target.value)}
                className="form-input w-full"
                placeholder="Enter last name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Mobile Number
              </label>
              <input
                type="text"
                value={searchCriteria.mobileNumber}
                onChange={(e) => handleInputChange('mobileNumber', e.target.value)}
                className="form-input w-full"
                placeholder="Enter mobile number"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Aadhaar Number
              </label>
              <input
                type="text"
                value={searchCriteria.aadhaarNumber}
                onChange={(e) => handleInputChange('aadhaarNumber', e.target.value)}
                className="form-input w-full"
                placeholder="Enter Aadhaar number"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                UHID
              </label>
              <input
                type="text"
                value={searchCriteria.uhid}
                onChange={(e) => handleInputChange('uhid', e.target.value)}
                className="form-input w-full"
                placeholder="Enter UHID"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Date of Birth
              </label>
              <input
                type="date"
                value={searchCriteria.dateOfBirth}
                onChange={(e) => handleInputChange('dateOfBirth', e.target.value)}
                className="form-input w-full"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Gender
              </label>
              <select
                value={searchCriteria.gender}
                onChange={(e) => handleInputChange('gender', e.target.value)}
                className="form-select w-full"
              >
                <option value="">All Genders</option>
                <option value="male">Male</option>
                <option value="female">Female</option>
                <option value="other">Other</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Blood Group
              </label>
              <select
                value={searchCriteria.bloodGroup}
                onChange={(e) => handleInputChange('bloodGroup', e.target.value)}
                className="form-select w-full"
              >
                <option value="">All Blood Groups</option>
                <option value="A">A</option>
                <option value="B">B</option>
                <option value="AB">AB</option>
                <option value="O">O</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Registration Type
              </label>
              <select
                value={searchCriteria.registrationType}
                onChange={(e) => handleInputChange('registrationType', e.target.value)}
                className="form-select w-full"
              >
                <option value="">All Types</option>
                <option value="standard">Standard</option>
                <option value="emergency">Emergency</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Registration Source
              </label>
              <select
                value={searchCriteria.registrationSource}
                onChange={(e) => handleInputChange('registrationSource', e.target.value)}
                className="form-select w-full"
              >
                <option value="">All Sources</option>
                <option value="walk_in">Walk-in</option>
                <option value="referral">Referral</option>
                <option value="emergency">Emergency</option>
                <option value="online">Online</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                State
              </label>
              <input
                type="text"
                value={searchCriteria.state}
                onChange={(e) => handleInputChange('state', e.target.value)}
                className="form-input w-full"
                placeholder="Enter state"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                District
              </label>
              <input
                type="text"
                value={searchCriteria.district}
                onChange={(e) => handleInputChange('district', e.target.value)}
                className="form-input w-full"
                placeholder="Enter district"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                City
              </label>
              <input
                type="text"
                value={searchCriteria.city}
                onChange={(e) => handleInputChange('city', e.target.value)}
                className="form-input w-full"
                placeholder="Enter city"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                PIN Code
              </label>
              <input
                type="text"
                value={searchCriteria.pinCode}
                onChange={(e) => handleInputChange('pinCode', e.target.value)}
                className="form-input w-full"
                placeholder="Enter PIN code"
              />
            </div>
          </div>

          {/* Search Actions */}
          <div className="flex items-center justify-between mt-6 pt-6 border-t border-gray-200">
            <div className="flex items-center space-x-3">
              <button
                onClick={handleSearch}
                disabled={isSearching}
                className="btn btn-primary"
              >
                <MagnifyingGlassIcon className="w-5 h-5 mr-2" />
                {isSearching ? 'Searching...' : 'Search'}
              </button>
              <button
                onClick={handleClearSearch}
                className="btn btn-secondary"
              >
                Clear
              </button>
            </div>

            <div className="flex items-center space-x-3">
              <label className="text-sm text-gray-700">Show:</label>
              <select
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
                className="form-select w-20"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Results */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Search Results</h2>
            <div className="text-sm text-gray-600">
              {totalPatients > 0 ? `${totalPatients} patient(s) found` : 'No patients found'}
            </div>
          </div>
        </div>
        <div className="card-body">
          {isLoading || isLoadingAll ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
              <span className="ml-2 text-gray-600">Loading patients...</span>
            </div>
          ) : error ? (
            <div className="text-center py-8">
              <div className="text-red-600 mb-2">Failed to load patients</div>
              <button
                onClick={() => refetch()}
                className="btn btn-secondary"
              >
                Try Again
              </button>
            </div>
          ) : patients.length === 0 ? (
            <div className="text-center py-8">
              <div className="text-gray-500 mb-2">No patients found</div>
              <p className="text-sm text-gray-400">
                Try adjusting your search criteria or register a new patient.
              </p>
            </div>
          ) : (
            <>
              {/* Patients Table */}
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Patient Info
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Contact
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Registration
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Location
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {patients.map((patient) => (
                      <tr key={patient.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div className="text-sm font-medium text-gray-900">
                              {patient.firstName} {patient.lastName || ''}
                            </div>
                            <div className="text-sm text-gray-500">
                              UHID: {patient.uhid || 'N/A'}
                            </div>
                            <div className="text-sm text-gray-500">
                              {getGenderDisplay(patient.gender)} • {patient.age || 'N/A'} years
                            </div>
                            {patient.bloodGroup && (
                              <div className="text-sm text-gray-500">
                                Blood: {patient.bloodGroup}
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {patient.mobileNumber || 'N/A'}
                          </div>
                          {patient.email && (
                            <div className="text-sm text-gray-500">
                              {patient.email}
                            </div>
                          )}
                          {patient.aadhaarNumber && (
                            <div className="text-sm text-gray-500">
                              Aadhaar: {patient.aadhaarNumber}
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {getRegistrationTypeDisplay(patient.registrationType)}
                          </div>
                          <div className="text-sm text-gray-500">
                            {getRegistrationTypeDisplay(patient.registrationSource)}
                          </div>
                          <div className="text-sm text-gray-500">
                            {formatDate(patient.createdAt)}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {patient.addresses && patient.addresses.length > 0 ? (
                            <div>
                              <div className="text-sm text-gray-900">
                                {patient.addresses[0].city || 'N/A'}, {patient.addresses[0].state || 'N/A'}
                              </div>
                              <div className="text-sm text-gray-500">
                                {patient.addresses[0].pinCode || 'N/A'}
                              </div>
                            </div>
                          ) : (
                            <div className="text-sm text-gray-500">No address</div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <div className="flex items-center space-x-2">
                            <Link
                              to={`/patient/${patient.id}`}
                              className="text-primary-600 hover:text-primary-900"
                            >
                              <EyeIcon className="w-5 h-5" />
                            </Link>
                            <Link
                              to={`/patient/${patient.id}/edit`}
                              className="text-secondary-600 hover:text-secondary-900"
                            >
                              <PencilIcon className="w-5 h-5" />
                            </Link>
                            <button
                              onClick={() => {
                                if (window.confirm('Are you sure you want to delete this patient?')) {
                                  // Handle delete
                                  toast.error('Delete functionality not implemented yet');
                                }
                              }}
                              className="text-red-600 hover:text-red-900"
                            >
                              <TrashIcon className="w-5 h-5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-6">
                  <div className="text-sm text-gray-700">
                    Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, totalPatients)} of {totalPatients} results
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={currentPage === 1}
                      className="btn btn-secondary btn-sm"
                    >
                      Previous
                    </button>
                    <span className="text-sm text-gray-700">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button
                      onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                      disabled={currentPage === totalPages}
                      className="btn btn-secondary btn-sm"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default PatientSearch; 