export interface Patient {
  id: string;
  firstName: string;
  middleName?: string;
  lastName?: string;
  dateOfBirth: string;
  age: number;
  gender: string;
  bloodGroup?: string;
  rhFactor?: string;
  maritalStatus?: string;
  nationality?: string;
  religion?: string;
  caste?: string;
  education?: string;
  occupation?: string;
  motherTongue?: string;
  mobileNumber: string;
  email?: string;
  emergencyContactName?: string;
  emergencyContact?: string;
  emergencyContactRel?: string;
  aadhaarNumber?: string;
  panNumber?: string;
  abhaId?: string;
  rationCardNumber?: string;
  registrationType: string;
  registrationSource: string;
  referredBy?: string;
  height?: number;
  weight?: number;
  bmi?: number;
  chronicConditions?: string;
  currentMedications?: string;
  familyMedicalHistory?: string;
  smokingStatus?: string;
  alcoholConsumption?: string;
  physicalActivity?: string;
  addresses: PatientAddress[];
  allergies: PatientAllergy[];
  biometricData?: BiometricData;
  consents?: ConsentData;
  uhid?: string;
  createdAt: string;
  updatedAt: string;
}

export interface PatientAddress {
  id?: string;
  type: 'permanent' | 'current' | 'office' | 'emergency';
  address: string;
  city: string;
  district: string;
  state: string;
  pinCode: string;
  subDistrict?: string;
  landmark?: string;
  isPrimary?: boolean;
}

export interface PatientAllergy {
  id: string;
  name: string;
  severity: 'mild' | 'severe';
  reaction?: string;
  notes?: string;
}

export interface BiometricData {
  fingerprint: {
    leftThumb: boolean;
    rightThumb: boolean;
    quality: number;
  };
  facial: {
    image: boolean;
    quality: number;
    livenessScore: number;
  };
}

export interface ConsentData {
  biometric: boolean;
  dataSharing: boolean;
  treatment: boolean;
  research: boolean;
}

export interface RegistrationFormData {
  // Basic Information
  firstName: string;
  middleName?: string;
  lastName?: string;
  dateOfBirth: string;
  age: number;
  gender: string;
  bloodGroup?: string;
  rhFactor?: string;
  maritalStatus?: string;
  nationality?: string;
  religion?: string;
  caste?: string;
  education?: string;
  occupation?: string;
  motherTongue?: string;

  // Contact Information
  mobileNumber: string;
  email?: string;
  emergencyContactName?: string;
  emergencyContact?: string;
  emergencyContactRel?: string;
  aadhaarNumber?: string;
  panNumber?: string;
  abhaId?: string;
  rationCardNumber?: string;
  registrationType: string;
  registrationSource: string;
  referredBy?: string;

  // Address Information
  addresses: PatientAddress[];

  // Medical Information
  height?: number;
  weight?: number;
  bmi?: number;
  chronicConditions?: string;
  currentMedications?: string;
  familyMedicalHistory?: string;
  smokingStatus?: string;
  alcoholConsumption?: string;
  physicalActivity?: string;
  allergies?: PatientAllergy[];

  // Biometric Data
  biometricData?: BiometricData;

  // Consents
  consents?: ConsentData;
}

export interface PatientSearchCriteria {
  firstName?: string;
  lastName?: string;
  mobileNumber?: string;
  aadhaarNumber?: string;
  abhaId?: string;
  uhid?: string;
  dateOfBirth?: string;
  age?: number;
  gender?: string;
  bloodGroup?: string;
  registrationType?: string;
  registrationSource?: string;
  state?: string;
  district?: string;
  city?: string;
  pinCode?: string;
  page?: number;
  limit?: number;
}

export interface PatientSearchResult {
  patients: Patient[];
  total: number;
  page: number;
  limit: number;
}

export interface DuplicateCheckResult {
  isDuplicate: boolean;
  confidence: number;
  matchedPatients?: Patient[];
  matchType?: 'biometric' | 'mobile' | 'name_dob' | 'aadhaar';
}

export interface RegistrationValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  duplicateCheck?: DuplicateCheckResult;
}

export interface UHIDGenerationResult {
  uhid: string;
  checksum: string;
  biometricHash?: string;
  generatedAt: string;
}

export interface RegistrationSubmissionResult {
  success: boolean;
  patientId: string;
  uhid: string;
  message: string;
  errors?: string[];
}



export interface FamilyMember {
  id: string;
  patientId: string;
  relationship: string;
  firstName: string;
  middleName?: string;
  lastName?: string;
  dateOfBirth: string;
  gender: string;
  mobileNumber?: string;
  isPrimaryContact: boolean;
}

export interface FamilyGroup {
  id: string;
  primaryContactId: string;
  familyName: string;
  members: FamilyMember[];
  createdAt: string;
  updatedAt: string;
}

export interface InsurancePolicy {
  id: string;
  patientId: string;
  policyNumber: string;
  insuranceProvider: string;
  policyType: string;
  startDate: string;
  endDate: string;
  premiumAmount: number;
  coverageAmount: number;
  isActive: boolean;
  documents?: string[];
  createdAt: string;
  updatedAt: string;
}

export interface AuditEvent {
  id: string;
  userId: string;
  patientId?: string;
  action: string;
  details: string;
  ipAddress: string;
  userAgent: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface Notification {
  id: string;
  patientId: string;
  type: 'registration' | 'appointment' | 'reminder' | 'alert';
  title: string;
  message: string;
  isRead: boolean;
  createdAt: string;
  scheduledFor?: string;
}

export interface PatientStatistics {
  totalPatients: number;
  newRegistrationsToday: number;
  patientsByGender: {
    male: number;
    female: number;
    other: number;
  };
  patientsByAgeGroup: {
    '0-18': number;
    '19-30': number;
    '31-50': number;
    '51-70': number;
    '70+': number;
  };
  patientsByBloodGroup: {
    [key: string]: number;
  };
  registrationsBySource: {
    walk_in: number;
    referral: number;
    online: number;
  };
}

export interface DashboardData {
  statistics: PatientStatistics;
  recentRegistrations: Patient[];
  upcomingAppointments: any[];
  alerts: Notification[];
  auditEvents: AuditEvent[];
} 