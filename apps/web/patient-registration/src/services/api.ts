import axios, { AxiosInstance, AxiosResponse } from 'axios';
import {
  Patient,
  PatientSearchCriteria,
  RegistrationFormData,
  PatientSearchResult,
  DuplicateCheckResult,
  RegistrationValidationResult,
  UHIDGenerationResult,
  RegistrationSubmissionResult,
  InsurancePolicy,
  AuditEvent,
  Notification,
  PatientStatistics,
  DashboardData,
} from '../types/patient';

// Define missing types that were removed
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  errors?: Record<string, string[]>;
}

interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

interface DuplicatePatientError {
  message: string;
  duplicates: Patient[];
}

class ApiService {
  private api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8082/api',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor
    this.api.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('authToken');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.api.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          // Handle unauthorized access
          localStorage.removeItem('authToken');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // Patient Registration
  async registerPatient(data: any): Promise<RegistrationSubmissionResult> {
    try {
      const response: AxiosResponse<ApiResponse<any>> = await this.api.post('/patients/register', data);
      
      // Transform the response to match expected format
      const result: RegistrationSubmissionResult = {
        success: response.data.success,
        patientId: response.data.data?.patientId || '',
        uhid: response.data.data?.uhid || '',
        message: response.data.data?.message || 'Patient registered successfully',
        errors: response.data.data?.errors || []
      };
      
      return result;
    } catch (error: any) {
      // Check for duplicate patient error (409 Conflict)
      if (error.response?.status === 409) {
        const duplicateError = new Error('A patient with this mobile number already exists');
        duplicateError.name = 'DuplicatePatientError';
        Object.assign(duplicateError, { 
          response: error.response,
          duplicates: error.response.data?.duplicates || []
        });
        throw duplicateError;
      }
      
      // Handle validation errors (400 Bad Request)
      if (error.response?.status === 400) {
        const validationError = new Error(error.response.data?.error || 'Invalid data provided');
        validationError.name = 'ValidationError';
        Object.assign(validationError, { response: error.response });
        throw validationError;
      }
      
      // Handle server errors (500 Internal Server Error)
      if (error.response?.status >= 500) {
        const serverError = new Error('Server error occurred. Please try again later.');
        serverError.name = 'ServerError';
        Object.assign(serverError, { response: error.response });
        throw serverError;
      }
      
      // Handle network errors
      if (!error.response) {
        const networkError = new Error('Network error. Please check your connection and try again.');
        networkError.name = 'NetworkError';
        throw networkError;
      }
      
      // Rethrow the original error if no specific handling
      throw error;
    }
  }



  // Patient Retrieval
  async getPatient(id: string): Promise<Patient> {
    const response: AxiosResponse<ApiResponse<Patient>> = await this.api.get(`/patients/${id}`);
    return response.data.data!;
  }

  async getPatientByUHID(uhid: string): Promise<Patient> {
    const response: AxiosResponse<ApiResponse<Patient>> = await this.api.get(`/patients/uhid/${uhid}`);
    return response.data.data!;
  }

  async getPatientByMobile(mobileNumber: string): Promise<Patient> {
    const response: AxiosResponse<ApiResponse<Patient>> = await this.api.get(`/patients/mobile/${mobileNumber}`);
    return response.data.data!;
  }

  // Patient Search
  async searchPatients(criteria: PatientSearchCriteria): Promise<PatientSearchResult> {
    const response: AxiosResponse<ApiResponse<PatientSearchResult>> = await this.api.post('/patients/search', criteria);
    return response.data.data!;
  }

  // Patient Update
  async updatePatient(id: string, data: Partial<RegistrationFormData>): Promise<Patient> {
    const response: AxiosResponse<ApiResponse<Patient>> = await this.api.put(`/patients/${id}`, data);
    return response.data.data!;
  }

  // Patient Deletion
  async deletePatient(id: string): Promise<void> {
    await this.api.delete(`/patients/${id}`);
  }





  // Address Management
  async addPatientAddress(patientId: string, address: any): Promise<any> {
    const response: AxiosResponse<ApiResponse<any>> = await this.api.post(`/patients/${patientId}/addresses`, address);
    return response.data.data!;
  }

  async updatePatientAddress(patientId: string, addressId: string, address: any): Promise<any> {
    const response: AxiosResponse<ApiResponse<any>> = await this.api.put(`/patients/${patientId}/addresses/${addressId}`, address);
    return response.data.data!;
  }

  async deletePatientAddress(patientId: string, addressId: string): Promise<void> {
    await this.api.delete(`/patients/${patientId}/addresses/${addressId}`);
  }

  // Allergy Management
  async addPatientAllergy(patientId: string, allergy: any): Promise<any> {
    const response: AxiosResponse<ApiResponse<any>> = await this.api.post(`/patients/${patientId}/allergies`, allergy);
    return response.data.data!;
  }

  async updatePatientAllergy(patientId: string, allergyId: string, allergy: any): Promise<any> {
    const response: AxiosResponse<ApiResponse<any>> = await this.api.put(`/patients/${patientId}/allergies/${allergyId}`, allergy);
    return response.data.data!;
  }

  async deletePatientAllergy(patientId: string, allergyId: string): Promise<void> {
    await this.api.delete(`/patients/${patientId}/allergies/${allergyId}`);
  }

  // Insurance Management
  async addInsurancePolicy(patientId: string, policy: any): Promise<InsurancePolicy> {
    const response: AxiosResponse<ApiResponse<InsurancePolicy>> = await this.api.post(`/patients/${patientId}/insurance`, policy);
    return response.data.data!;
  }

  async updateInsurancePolicy(patientId: string, policyId: string, policy: any): Promise<InsurancePolicy> {
    const response: AxiosResponse<ApiResponse<InsurancePolicy>> = await this.api.put(`/patients/${patientId}/insurance/${policyId}`, policy);
    return response.data.data!;
  }

  async deleteInsurancePolicy(patientId: string, policyId: string): Promise<void> {
    await this.api.delete(`/patients/${patientId}/insurance/${policyId}`);
  }

  // Utility Methods
  async checkDuplicatePatient(data: Partial<RegistrationFormData>): Promise<DuplicateCheckResult> {
    const response: AxiosResponse<ApiResponse<DuplicateCheckResult>> = await this.api.post('/patients/check-duplicate', data);
    return response.data.data!;
  }

  async getPINCodeDetails(pinCode: string): Promise<any> {
    const response: AxiosResponse<ApiResponse<any>> = await this.api.get(`/utils/pincode/${pinCode}`);
    return response.data.data!;
  }

  async validateAadhaar(aadhaarNumber: string): Promise<boolean> {
    const response: AxiosResponse<ApiResponse<boolean>> = await this.api.get(`/utils/validate/aadhaar?value=${aadhaarNumber}`);
    return response.data.data!;
  }

  async validatePAN(panNumber: string): Promise<boolean> {
    const response: AxiosResponse<ApiResponse<boolean>> = await this.api.get(`/utils/validate/pan?value=${panNumber}`);
    return response.data.data!;
  }

  async validateMobile(mobileNumber: string): Promise<boolean> {
    const response: AxiosResponse<ApiResponse<boolean>> = await this.api.get(`/utils/validate/mobile?value=${mobileNumber}`);
    return response.data.data!;
  }

  // File Upload
  async uploadDocument(file: File, type: string): Promise<string> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('type', type);

    const response: AxiosResponse<ApiResponse<{ url: string }>> = await this.api.post('/upload/document', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data.data!.url;
  }



  // Dashboard and Statistics
  async getDashboardData(): Promise<DashboardData> {
    const response: AxiosResponse<ApiResponse<DashboardData>> = await this.api.get('/dashboard');
    return response.data.data!;
  }

  async getPatientStatistics(): Promise<PatientStatistics> {
    const response: AxiosResponse<ApiResponse<PatientStatistics>> = await this.api.get('/statistics/patients');
    return response.data.data!;
  }

  // Error Handling
  handleError(error: any): never {
    if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    }
    if (error.response?.data?.message) {
      throw new Error(error.response.data.message);
    }
    if (error.response?.data?.details) {
      throw new Error(error.response.data.details);
    }
    if (error.message) {
      throw new Error(error.message);
    }
    throw new Error('An unexpected error occurred');
  }

  // Check if error is a duplicate patient error
  isDuplicatePatientError(error: any): error is DuplicatePatientError {
    return error.response?.status === 409 && error.response?.data?.duplicates;
  }
}

export const apiService = new ApiService();
export default apiService;