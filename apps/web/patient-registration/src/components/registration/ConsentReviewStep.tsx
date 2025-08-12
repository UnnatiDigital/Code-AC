import React, { useState, useEffect } from 'react';
import { useFormContext } from 'react-hook-form';
import { RegistrationFormData } from '../../types/patient';

const ConsentReviewStep: React.FC = () => {
  const { watch, setValue } = useFormContext<RegistrationFormData>();
  const [consents, setConsents] = useState({
    biometric: false,
    dataSharing: false,
    treatment: false,
    research: false
  });
  const [showReview, setShowReview] = useState(false);

  const formData = watch();

  // Initialize consents from form data if available
  useEffect(() => {
    if (formData.consents) {
      setConsents(formData.consents);
    }
  }, [formData.consents]);

  const handleConsentChange = (consentType: keyof typeof consents) => {
    const newConsents = {
      ...consents,
      [consentType]: !consents[consentType]
    };
    setConsents(newConsents);
    
    // Update form data with consent values
    setValue('consents', newConsents);
  };

  const allConsentsGiven = Object.values(consents).every(consent => consent);

  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h3 className="text-lg font-semibold text-gray-900">Consent & Review</h3>
        <p className="text-sm text-gray-600">Review patient information and provide necessary consents</p>
      </div>

      {/* Digital Consent Forms */}
      <div className="space-y-6">
        <h4 className="text-md font-semibold text-gray-900">Digital Consent Forms</h4>

        {/* Biometric Consent */}
        <div className="border border-gray-200 rounded-lg p-6">
          <div className="flex items-start space-x-3">
            <input
              type="checkbox"
              id="biometric-consent"
              checked={consents.biometric}
              onChange={() => handleConsentChange('biometric')}
              className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <div className="flex-1">
              <label htmlFor="biometric-consent" className="text-sm font-medium text-gray-900 cursor-pointer">
                Biometric Data Collection Consent
              </label>
              <p className="text-sm text-gray-600 mt-1">
                I consent to the collection, storage, and use of my biometric data (fingerprints, facial images) 
                for the purpose of patient identification and healthcare services. I understand that this data 
                will be stored securely and used only for authorized healthcare purposes.
              </p>
              <div className="mt-2 text-xs text-gray-500">
                <p>• Biometric data will be encrypted and stored securely</p>
                <p>• Data will be used only for patient identification</p>
                <p>• You can withdraw consent at any time</p>
                <p>• Data will be retained as per healthcare regulations</p>
              </div>
            </div>
          </div>
        </div>

        {/* Data Sharing Consent */}
        <div className="border border-gray-200 rounded-lg p-6">
          <div className="flex items-start space-x-3">
            <input
              type="checkbox"
              id="data-sharing-consent"
              checked={consents.dataSharing}
              onChange={() => handleConsentChange('dataSharing')}
              className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <div className="flex-1">
              <label htmlFor="data-sharing-consent" className="text-sm font-medium text-gray-900 cursor-pointer">
                Healthcare Data Sharing Consent
              </label>
              <p className="text-sm text-gray-600 mt-1">
                I consent to the sharing of my healthcare information with authorized healthcare providers, 
                insurance companies, and government health agencies as required for treatment, billing, 
                and public health purposes.
              </p>
              <div className="mt-2 text-xs text-gray-500">
                <p>• Information shared only with authorized entities</p>
                <p>• Used for treatment, billing, and public health</p>
                <p>• Protected under healthcare privacy laws</p>
                <p>• You can request information about data sharing</p>
              </div>
            </div>
          </div>
        </div>

        {/* Treatment Consent */}
        <div className="border border-gray-200 rounded-lg p-6">
          <div className="flex items-start space-x-3">
            <input
              type="checkbox"
              id="treatment-consent"
              checked={consents.treatment}
              onChange={() => handleConsentChange('treatment')}
              className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <div className="flex-1">
              <label htmlFor="treatment-consent" className="text-sm font-medium text-gray-900 cursor-pointer">
                General Treatment Consent
              </label>
              <p className="text-sm text-gray-600 mt-1">
                I consent to receive medical treatment and care from this healthcare facility. I understand 
                that I have the right to refuse any treatment and to be informed about my medical condition 
                and treatment options.
              </p>
              <div className="mt-2 text-xs text-gray-500">
                <p>• You have the right to refuse treatment</p>
                <p>• You will be informed about treatment options</p>
                <p>• You can ask questions about your care</p>
                <p>• Emergency treatment may be provided without consent if necessary</p>
              </div>
            </div>
          </div>
        </div>

        {/* Research Consent */}
        <div className="border border-gray-200 rounded-lg p-6">
          <div className="flex items-start space-x-3">
            <input
              type="checkbox"
              id="research-consent"
              checked={consents.research}
              onChange={() => handleConsentChange('research')}
              className="mt-1 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <div className="flex-1">
              <label htmlFor="research-consent" className="text-sm font-medium text-gray-900 cursor-pointer">
                Research Participation Consent (Optional)
              </label>
              <p className="text-sm text-gray-600 mt-1">
                I consent to participate in medical research studies that may be conducted by this facility. 
                I understand that participation is voluntary and I can withdraw at any time.
              </p>
              <div className="mt-2 text-xs text-gray-500">
                <p>• Participation is completely voluntary</p>
                <p>• You can withdraw at any time</p>
                <p>• Your privacy will be protected</p>
                <p>• You will be informed about research findings</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Consent Status */}
      <div className={`p-4 rounded-md ${
        allConsentsGiven ? 'bg-green-50 border border-green-200' : 'bg-yellow-50 border border-yellow-200'
      }`}>
        <div className="flex items-center">
          <div className={`flex-shrink-0 w-3 h-3 rounded-full ${
            allConsentsGiven ? 'bg-green-400' : 'bg-yellow-400'
          }`}></div>
          <div className="ml-3">
            <p className={`text-sm font-medium ${
              allConsentsGiven ? 'text-green-800' : 'text-yellow-800'
            }`}>
              {allConsentsGiven ? 'All Required Consents Provided' : 'Required Consents Pending'}
            </p>
            <p className={`text-sm ${
              allConsentsGiven ? 'text-green-700' : 'text-yellow-700'
            }`}>
              {allConsentsGiven 
                ? 'You can proceed with registration' 
                : 'Please provide all required consents to continue'
              }
            </p>
          </div>
        </div>
      </div>

      {/* Form Review Section */}
      <div className="border-t pt-6">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-md font-semibold text-gray-900">Registration Review</h4>
          <button
            type="button"
            onClick={() => setShowReview(!showReview)}
            className="text-blue-600 hover:text-blue-800 text-sm font-medium"
          >
            {showReview ? 'Hide Review' : 'Show Review'}
          </button>
        </div>

        {showReview && (
          <div className="bg-gray-50 rounded-lg p-6 space-y-6">
            {/* Basic Information Review */}
            <div>
              <h5 className="font-medium text-gray-900 mb-3">Basic Information</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Name:</span>
                  <span className="ml-2 font-medium">
                    {formData.firstName} {formData.middleName} {formData.lastName}
                  </span>
                </div>
                <div>
                  <span className="text-gray-600">Date of Birth:</span>
                  <span className="ml-2 font-medium">{formData.dateOfBirth}</span>
                </div>
                <div>
                  <span className="text-gray-600">Age:</span>
                  <span className="ml-2 font-medium">{formData.age} years</span>
                </div>
                <div>
                  <span className="text-gray-600">Gender:</span>
                  <span className="ml-2 font-medium capitalize">{formData.gender}</span>
                </div>
                <div>
                  <span className="text-gray-600">Blood Group:</span>
                  <span className="ml-2 font-medium">{formData.bloodGroup || 'Not specified'}</span>
                </div>
                <div>
                  <span className="text-gray-600">Mobile:</span>
                  <span className="ml-2 font-medium">{formData.mobileNumber}</span>
                </div>
              </div>
            </div>

            {/* Address Review */}
            <div>
              <h5 className="font-medium text-gray-900 mb-3">Address Information</h5>
              {formData.addresses && formData.addresses[0] && (
                <div className="text-sm">
                  <p className="font-medium">{formData.addresses[0].address}</p>
                  <p className="text-gray-600">
                    {formData.addresses[0].city}, {formData.addresses[0].district}, {formData.addresses[0].state} - {formData.addresses[0].pinCode}
                  </p>
                </div>
              )}
            </div>

            {/* Medical Information Review */}
            <div>
              <h5 className="font-medium text-gray-900 mb-3">Medical Information</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Height:</span>
                  <span className="ml-2 font-medium">{formData.height || 'Not specified'} cm</span>
                </div>
                <div>
                  <span className="text-gray-600">Weight:</span>
                  <span className="ml-2 font-medium">{formData.weight || 'Not specified'} kg</span>
                </div>
                <div>
                  <span className="text-gray-600">BMI:</span>
                  <span className="ml-2 font-medium">{formData.bmi || 'Not calculated'}</span>
                </div>
                <div>
                  <span className="text-gray-600">Registration Type:</span>
                  <span className="ml-2 font-medium capitalize">{formData.registrationType}</span>
                </div>
              </div>
            </div>

            {/* Emergency Contact Review */}
            <div>
              <h5 className="font-medium text-gray-900 mb-3">Emergency Contact</h5>
              <div className="text-sm">
                <p className="font-medium">{formData.emergencyContactName || 'Not specified'}</p>
                <p className="text-gray-600">{formData.emergencyContact || 'Not specified'}</p>
                <p className="text-gray-600 capitalize">{formData.emergencyContactRel || 'Not specified'}</p>
              </div>
            </div>

            {/* ID Documents Review */}
            <div>
              <h5 className="font-medium text-gray-900 mb-3">Identification Documents</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Aadhaar:</span>
                  <span className="ml-2 font-medium">{formData.aadhaarNumber || 'Not provided'}</span>
                </div>
                <div>
                  <span className="text-gray-600">PAN:</span>
                  <span className="ml-2 font-medium">{formData.panNumber || 'Not provided'}</span>
                </div>
                <div>
                  <span className="text-gray-600">ABHA ID:</span>
                  <span className="ml-2 font-medium">{formData.abhaId || 'Not provided'}</span>
                </div>
                <div>
                  <span className="text-gray-600">Ration Card:</span>
                  <span className="ml-2 font-medium">{formData.rationCardNumber || 'Not provided'}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Final Declaration */}
      <div className="border-t pt-6">
        <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-blue-800">Declaration</h3>
              <div className="mt-2 text-sm text-blue-700">
                <p>I declare that all information provided in this registration form is true and accurate to the best of my knowledge.</p>
                <p className="mt-1">I understand that providing false information may result in denial of services or legal consequences.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConsentReviewStep; 