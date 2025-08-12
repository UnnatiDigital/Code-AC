import React from 'react';
import { useFormContext } from 'react-hook-form';
import toast from 'react-hot-toast';
import { RegistrationFormData } from '../../types/patient';

const BiometricCaptureStep: React.FC = () => {
  const { register, watch, setValue, formState: { errors } } = useFormContext<RegistrationFormData>();
  
  const biometricData = watch('biometricData');

  const handleFingerprintCapture = () => {
    // Simulate fingerprint capture
    setValue('biometricData.fingerprint.leftThumb', true);
    setValue('biometricData.fingerprint.rightThumb', true);
    setValue('biometricData.fingerprint.quality', 85);
    toast.success('Fingerprint captured successfully!');
  };

  const handleFacialCapture = () => {
    // Simulate facial capture
    setValue('biometricData.facial.image', true);
    setValue('biometricData.facial.quality', 90);
    setValue('biometricData.facial.livenessScore', 95);
    toast.success('Facial image captured successfully!');
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900">Biometric Capture</h2>
        <p className="mt-2 text-gray-600">
          Capture patient biometric data for secure identification
        </p>
      </div>

      {/* Biometric Capture Options */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Fingerprint Capture */}
        <div className="card">
          <div className="card-body">
            <div className="text-center">
              <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-primary-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Fingerprint Capture</h3>
              <p className="text-sm text-gray-600 mb-4">
                Capture fingerprints for secure patient identification
              </p>
              
              <div className="space-y-3 mb-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-700">Left Thumb</span>
                  <div className="flex items-center">
                    {biometricData?.fingerprint?.leftThumb ? (
                      <div className="w-4 h-4 bg-green-500 rounded-full flex items-center justify-center">
                        <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      </div>
                    ) : (
                      <div className="w-4 h-4 bg-gray-300 rounded-full"></div>
                    )}
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-700">Right Thumb</span>
                  <div className="flex items-center">
                    {biometricData?.fingerprint?.rightThumb ? (
                      <div className="w-4 h-4 bg-green-500 rounded-full flex items-center justify-center">
                        <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      </div>
                    ) : (
                      <div className="w-4 h-4 bg-gray-300 rounded-full"></div>
                    )}
                  </div>
                </div>
                {biometricData?.fingerprint?.quality && biometricData.fingerprint.quality > 0 && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700">Quality</span>
                    <span className="text-sm font-medium text-green-600">{biometricData.fingerprint.quality}%</span>
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={handleFingerprintCapture}
                className="btn btn-primary w-full"
              >
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                </svg>
                Capture Fingerprints
              </button>
            </div>
          </div>
        </div>

        {/* Facial Recognition */}
        <div className="card">
          <div className="card-body">
            <div className="text-center">
              <div className="w-16 h-16 bg-secondary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-secondary-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Facial Recognition</h3>
              <p className="text-sm text-gray-600 mb-4">
                Capture facial image for biometric identification
              </p>
              
              <div className="space-y-3 mb-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-700">Facial Image</span>
                  <div className="flex items-center">
                    {biometricData?.facial?.image ? (
                      <div className="w-4 h-4 bg-green-500 rounded-full flex items-center justify-center">
                        <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      </div>
                    ) : (
                      <div className="w-4 h-4 bg-gray-300 rounded-full"></div>
                    )}
                  </div>
                </div>
                {biometricData?.facial?.quality && biometricData.facial.quality > 0 && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700">Quality</span>
                    <span className="text-sm font-medium text-green-600">{biometricData.facial.quality}%</span>
                  </div>
                )}
                {biometricData?.facial?.livenessScore && biometricData.facial.livenessScore > 0 && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700">Liveness Score</span>
                    <span className="text-sm font-medium text-blue-600">{biometricData.facial.livenessScore}%</span>
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={handleFacialCapture}
                className="btn btn-secondary w-full"
              >
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
                Capture Facial Image
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Capture All Button */}
      <div className="card">
        <div className="card-body">
          <div className="text-center">
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Capture All Biometric Data</h3>
            <p className="text-sm text-gray-600 mb-4">
              Capture both fingerprint and facial data in one go
            </p>
            <button
              type="button"
              onClick={() => {
                handleFingerprintCapture();
                handleFacialCapture();
              }}
              className="btn btn-success w-full"
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Capture All Biometric Data
            </button>
          </div>
        </div>
      </div>

      {/* Information */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex">
          <div className="flex-shrink-0">
            <svg className="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-blue-800">Biometric Data Security</h3>
            <div className="mt-2 text-sm text-blue-700">
              <p>• All biometric data is encrypted and stored securely</p>
              <p>• Data is used only for patient identification</p>
              <p>• High-quality capture ensures accurate identification</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BiometricCaptureStep;
