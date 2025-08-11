import React, { useState } from 'react';
import { useForm, FormProvider } from 'react-hook-form';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import BasicInformationStep from './BasicInformationStep';
import ContactInformationStep from './ContactInformationStep';
import AddressInformationStep from './AddressInformationStep';
import MedicalInformationStep from './MedicalInformationStep';
import BiometricCaptureStep from './BiometricCaptureStep';
import ConsentReviewStep from './ConsentReviewStep';
import { RegistrationFormData, PatientAllergy } from '@/types/patient';
import apiService from '@/services/api';

const STEPS = [
  { id: 1, title: 'Basic Information', component: BasicInformationStep },
  { id: 2, title: 'Contact & ID', component: ContactInformationStep },
  { id: 3, title: 'Address', component: AddressInformationStep },
  { id: 4, title: 'Medical Info', component: MedicalInformationStep },
  { id: 5, title: 'Biometric Capture', component: BiometricCaptureStep },
  { id: 6, title: 'Consent & Review', component: ConsentReviewStep },
];

const MultiStepRegistrationForm: React.FC = () => {
  const [currentStep, setCurrentStep] = useState(1);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isCheckingDuplicate, setIsCheckingDuplicate] = useState(false);
  const navigate = useNavigate();

  const methods = useForm<RegistrationFormData>({
    defaultValues: {
      firstName: '',
      middleName: '',
      lastName: '',
      dateOfBirth: '',
      age: 0,
      gender: '',
      bloodGroup: '',
      rhFactor: '',
      maritalStatus: '',
      nationality: 'Indian',
      religion: '',
      caste: '',
      education: '',
      occupation: '',
      motherTongue: '',
      mobileNumber: '',
      email: '',
      emergencyContactName: '',
      emergencyContact: '',
      emergencyContactRel: '',
      aadhaarNumber: '',
      panNumber: '',
      abhaId: '',
      rationCardNumber: '',
      registrationType: 'standard',
      registrationSource: 'walk_in',
      referredBy: '',
      height: undefined,
      weight: undefined,
      bmi: undefined,
      chronicConditions: '',
      currentMedications: '',
      familyMedicalHistory: '',
      smokingStatus: '',
      alcoholConsumption: '',
      physicalActivity: '',
      allergies: [],
      addresses: [
        {
          type: 'permanent',
          address: '',
          city: '',
          district: '',
          state: '',
          pinCode: '',
          subDistrict: '',
          landmark: '',
          isPrimary: true
        }
      ],

      biometricData: {
        fingerprint: {
          leftThumb: false,
          rightThumb: false,
          quality: 0
        },
        facial: {
          image: false,
          quality: 0,
          livenessScore: 0
        }
      },
      consents: {
        biometric: false,
        dataSharing: false,
        treatment: false,
        research: false
      }
    },
    mode: 'onChange'
  });

  const { handleSubmit, trigger, formState: { errors, isValid } } = methods;

  const nextStep = async () => {
    const fieldsToValidate = getFieldsForStep(currentStep);
    const isStepValid = await trigger(fieldsToValidate);
    
    if (isStepValid) {
      if (currentStep < STEPS.length) {
        setCurrentStep(currentStep + 1);
        window.scrollTo(0, 0);
      }
    } else {
      toast.error('Please fill all required fields correctly before proceeding.');
    }
  };

  const prevStep = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
      window.scrollTo(0, 0);
    }
  };

  const getFieldsForStep = (step: number): (keyof RegistrationFormData)[] => {
    switch (step) {
      case 1: // Basic Information
        return ['firstName', 'dateOfBirth', 'gender'];
      case 2: // Contact & ID
        return ['mobileNumber', 'registrationType', 'registrationSource'];
      case 3: // Address
        return ['addresses'];
      case 4: // Medical Info
        return [];
      case 5: // Biometric Capture
        return ['biometricData'];
      case 6: // Consent & Review
        return ['consents'];
      default:
        return [];
    }
  };

  const onSubmit = async (data: RegistrationFormData) => {
    try {
      setIsSubmitting(true);
      
      // Validate required consents
      if (!data.consents?.treatment) {
        toast.error('Treatment consent is required');
        return;
      }

      // Validate mobile number format
      const mobileRegex = /^[6-9]\d{9}$/;
      if (!mobileRegex.test(data.mobileNumber)) {
        toast.error('Please enter a valid 10-digit mobile number starting with 6-9');
        return;
      }

      // Check for duplicate patient before submission
      setIsCheckingDuplicate(true);
      try {
        const duplicateCheck = await apiService.checkDuplicatePatient({
          mobileNumber: data.mobileNumber,
          firstName: data.firstName,
          lastName: data.lastName,
          dateOfBirth: data.dateOfBirth
        });
        
        if (duplicateCheck.isDuplicate && duplicateCheck.matchedPatients && duplicateCheck.matchedPatients.length > 0) {
          const duplicate = duplicateCheck.matchedPatients[0];
          toast.error(`A patient with mobile number ${data.mobileNumber} already exists (UHID: ${duplicate.uhid})`);
          return;
        }
      } catch (error) {
        // If duplicate check fails, continue with registration (backend will handle it)
        console.warn('Duplicate check failed, proceeding with registration:', error);
      } finally {
        setIsCheckingDuplicate(false);
      }
      
      // Transform form data to API format
      const transformedData = {
        basicInfo: {
          firstName: data.firstName,
          middleName: data.middleName || '',
          lastName: data.lastName || '',
          dateOfBirth: data.dateOfBirth,
          gender: data.gender.toLowerCase(), // Convert to lowercase to match backend expectations
          bloodGroup: data.bloodGroup?.replace(/\+|-/g, '') || '', // Remove + or - from blood group
          maritalStatus: data.maritalStatus || 'single' // Provide default value if not specified
        },
        contactInfo: {
          mobileNumber: data.mobileNumber,
          email: data.email || '',
          emergencyContact: {
            name: data.emergencyContactName || '',
            relationship: data.emergencyContactRel || '',
            mobileNumber: data.emergencyContact || ''
          }
        },
        addressInfo: data.addresses.map(addr => ({
          type: addr.type.toLowerCase(), // Convert to lowercase to match backend expectations
          addressLine1: addr.address,
          addressLine2: addr.landmark || '',
          city: addr.city,
          state: addr.state,
          district: addr.district || addr.city, // Use city as district if not provided
          pinCode: addr.pinCode,
          country: 'India'
        })),
        medicalInfo: {
          allergies: data.allergies?.map((allergy: PatientAllergy) => ({
            allergen: allergy.name,
            severity: allergy.severity,
            reaction: allergy.reaction || '',
            notes: allergy.notes || ''
          })) || [],
          medicalHistory: data.familyMedicalHistory || '',
          currentMedications: data.currentMedications ? [data.currentMedications] : []
        },
        insuranceInfo: [],
        documents: {
          aadhaarNumber: data.aadhaarNumber || '',
          panNumber: data.panNumber || '',
          abhaId: data.abhaId || ''
        },
        consents: {
          biometric: data.consents?.biometric || false,
          dataSharing: data.consents?.dataSharing || false,
          treatment: data.consents?.treatment || false,
          research: data.consents?.research || false
        }
      };

      try {
        // Call the actual API
        const result = await apiService.registerPatient(transformedData);
        
        toast.success(`Registration successful! UHID: ${result.uhid}`);
        
        // Navigate to success page or dashboard
        navigate('/dashboard', { 
          state: { 
            registrationSuccess: true, 
            uhid: result.uhid,
            patientData: data 
          } 
        });
      } catch (error: any) {
        console.error('Registration error:', error);
        
        // Handle different types of errors
        if (error.name === 'DuplicatePatientError') {
          toast.error('A patient with this mobile number already exists. Please use a different mobile number or check if the patient is already registered.');
          
          // Show duplicate patient details if available
          if (error.duplicates && error.duplicates.length > 0) {
            const duplicate = error.duplicates[0];
            toast.error(`Found existing patient: ${duplicate.first_name} ${duplicate.last_name || ''} (UHID: ${duplicate.uhid})`);
          }
        } 
        else if (error.name === 'ValidationError') {
          toast.error(`Validation error: ${error.message}`);
        }
        else if (error.name === 'ServerError') {
          toast.error('Server error occurred. Please try again later.');
        }
        else if (error.name === 'NetworkError') {
          toast.error('Network error. Please check your connection and try again.');
        }
        // Handle legacy error format
        else if (error.response?.status === 409) {
          toast.error('A patient with this mobile number already exists');
        } 
        else if (error.response?.status === 400) {
          const errorMessage = error.response.data.details || error.response.data.error || 'Invalid data provided';
          toast.error(`Registration failed: ${errorMessage}`);
        } 
        else {
          toast.error('Registration failed. Please try again.');
        }
      }
    } catch (error) {
      console.error('Form processing error:', error);
      toast.error('An error occurred while processing the form. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };



  const CurrentStepComponent = STEPS[currentStep - 1].component;

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Patient Registration</h1>
          <p className="mt-2 text-gray-600">Complete the registration form to create a new patient record</p>
        </div>

        {/* Progress Bar */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            {STEPS.map((step, index) => (
              <div key={step.id} className="flex items-center">
                <div className={`flex items-center justify-center w-10 h-10 rounded-full border-2 ${
                  currentStep > step.id
                    ? 'bg-green-500 border-green-500 text-white'
                    : currentStep === step.id
                    ? 'bg-blue-500 border-blue-500 text-white'
                    : 'bg-white border-gray-300 text-gray-500'
                }`}>
                  {currentStep > step.id ? (
                    <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  ) : (
                    <span className="text-sm font-medium">{step.id}</span>
                  )}
                </div>
                {index < STEPS.length - 1 && (
                  <div className={`flex-1 h-1 mx-4 ${
                    currentStep > step.id ? 'bg-green-500' : 'bg-gray-300'
                  }`} />
                )}
              </div>
            ))}
          </div>
          
          {/* Step Labels */}
          <div className="flex justify-between mt-4">
            {STEPS.map((step) => (
              <div key={step.id} className="text-center">
                <span className={`text-sm font-medium ${
                  currentStep >= step.id ? 'text-blue-600' : 'text-gray-500'
                }`}>
                  {step.title}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Form */}
        <FormProvider {...methods}>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-xl font-semibold text-gray-900">
                  Step {currentStep}: {STEPS[currentStep - 1].title}
                </h2>
                <p className="mt-1 text-sm text-gray-600">
                  {currentStep === 1 && 'Enter the patient\'s basic personal information'}
                  {currentStep === 2 && 'Provide contact details and identification information'}
                  {currentStep === 3 && 'Enter address information with PIN code auto-population'}
                  {currentStep === 4 && 'Record medical information and allergies'}
                  {currentStep === 5 && 'Capture biometric data for secure identification'}
                  {currentStep === 6 && 'Review information and provide necessary consents'}
                </p>
              </div>
              
              <div className="px-6 py-6">
                <CurrentStepComponent />
              </div>
            </div>

            {/* Navigation Buttons */}
            <div className="flex justify-between">
              <button
                type="button"
                onClick={prevStep}
                disabled={currentStep === 1}
                className={`px-6 py-2 border border-gray-300 rounded-md text-sm font-medium ${
                  currentStep === 1
                    ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                    : 'bg-white text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500'
                }`}
              >
                Previous
              </button>

              <div className="flex space-x-3">
                {currentStep < STEPS.length ? (
                  <button
                    type="button"
                    onClick={nextStep}
                    className="px-6 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    Next
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={isSubmitting || isCheckingDuplicate || !isValid}
                    className={`px-6 py-2 rounded-md text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      isSubmitting || isCheckingDuplicate || !isValid
                        ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                        : 'bg-green-600 text-white hover:bg-green-700'
                    }`}
                  >
                    {isCheckingDuplicate ? (
                      <div className="flex items-center">
                        <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Checking...
                      </div>
                    ) : isSubmitting ? (
                      <div className="flex items-center">
                        <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Processing...
                      </div>
                    ) : (
                      'Complete Registration'
                    )}
                  </button>
                )}
              </div>
            </div>
          </form>
        </FormProvider>

        {/* Form Validation Summary */}
        {Object.keys(errors).length > 0 && (
          <div className="mt-6 bg-red-50 border border-red-200 rounded-md p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800">Form Validation Errors</h3>
                <div className="mt-2 text-sm text-red-700">
                  <ul className="list-disc pl-5 space-y-1">
                    {Object.entries(errors).map(([field, error]) => (
                      <li key={field}>
                        {field}: {error?.message || 'This field is required'}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Help Information */}
        <div className="mt-8 bg-blue-50 border border-blue-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-blue-800">Registration Help</h3>
              <div className="mt-2 text-sm text-blue-700">
                <p>• All fields marked with * are required</p>
                <p>• You can navigate between steps using Previous/Next buttons</p>

                <p>• All consents must be provided to complete registration</p>
                <p>• UHID will be generated automatically upon successful registration</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MultiStepRegistrationForm;