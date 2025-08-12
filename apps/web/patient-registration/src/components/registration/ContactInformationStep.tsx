import React from 'react';
import { useFormContext } from 'react-hook-form';
import { RegistrationFormData } from '../../types/patient';

const ContactInformationStep: React.FC = () => {
  const { register, formState: { errors } } = useFormContext<RegistrationFormData>();

  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h3 className="text-lg font-semibold text-gray-900">Contact Information</h3>
        <p className="text-sm text-gray-600">Enter the patient's contact details</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Mobile Number */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Mobile Number *
          </label>
          <input
            type="tel"
            {...register('mobileNumber', {
              required: 'Mobile number is required',
              pattern: {
                value: /^[6-9]\d{9}$/,
                message: 'Please enter a valid 10-digit Indian mobile number'
              }
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.mobileNumber ? 'border-red-500' : 'border-gray-300'
            }`}
            placeholder="Enter 10-digit mobile number"
            maxLength={10}
          />
          {errors.mobileNumber && (
            <p className="mt-1 text-sm text-red-600">{errors.mobileNumber.message}</p>
          )}
        </div>

        {/* Email */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Email Address
          </label>
          <input
            type="email"
            {...register('email', {
              pattern: {
                value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                message: 'Please enter a valid email address'
              }
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.email ? 'border-red-500' : 'border-gray-300'
            }`}
            placeholder="Enter email address"
          />
          {errors.email && (
            <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>
          )}
        </div>
      </div>

      {/* Emergency Contact Section */}
      <div className="border-t pt-6">
        <h4 className="text-md font-semibold text-gray-900 mb-4">Emergency Contact</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Emergency Contact Name */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Emergency Contact Name
            </label>
            <input
              type="text"
              {...register('emergencyContactName', {
                maxLength: { value: 100, message: 'Name must be less than 100 characters' },
                pattern: {
                  value: /^[a-zA-Z\u00C0-\u017F\s]+$/,
                  message: 'Name can only contain letters and spaces'
                }
              })}
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.emergencyContactName ? 'border-red-500' : 'border-gray-300'
              }`}
              placeholder="Enter emergency contact name"
            />
            {errors.emergencyContactName && (
              <p className="mt-1 text-sm text-red-600">{errors.emergencyContactName.message}</p>
            )}
          </div>

          {/* Emergency Contact Number */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Emergency Contact Number
            </label>
            <input
              type="tel"
              {...register('emergencyContact', {
                pattern: {
                  value: /^[6-9]\d{9}$/,
                  message: 'Please enter a valid 10-digit Indian mobile number'
                }
              })}
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.emergencyContact ? 'border-red-500' : 'border-gray-300'
              }`}
              placeholder="Enter emergency contact number"
              maxLength={10}
            />
            {errors.emergencyContact && (
              <p className="mt-1 text-sm text-red-600">{errors.emergencyContact.message}</p>
            )}
          </div>

          {/* Emergency Contact Relationship */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Relationship
            </label>
            <select
              {...register('emergencyContactRel')}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select Relationship</option>
              <option value="spouse">Spouse</option>
              <option value="father">Father</option>
              <option value="mother">Mother</option>
              <option value="son">Son</option>
              <option value="daughter">Daughter</option>
              <option value="brother">Brother</option>
              <option value="sister">Sister</option>
              <option value="guardian">Guardian</option>
              <option value="friend">Friend</option>
              <option value="other">Other</option>
            </select>
          </div>
        </div>
      </div>

      {/* ID Documents Section */}
      <div className="border-t pt-6">
        <h4 className="text-md font-semibold text-gray-900 mb-4">Identification Documents</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Aadhaar Number */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Aadhaar Number
            </label>
            <input
              type="text"
              {...register('aadhaarNumber', {
                pattern: {
                  value: /^\d{12}$/,
                  message: 'Aadhaar number must be 12 digits'
                }
              })}
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.aadhaarNumber ? 'border-red-500' : 'border-gray-300'
              }`}
              placeholder="Enter 12-digit Aadhaar number"
              maxLength={12}
            />
            {errors.aadhaarNumber && (
              <p className="mt-1 text-sm text-red-600">{errors.aadhaarNumber.message}</p>
            )}
          </div>

          {/* PAN Number */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              PAN Number
            </label>
            <input
              type="text"
              {...register('panNumber', {
                pattern: {
                  value: /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/,
                  message: 'Please enter a valid PAN number (e.g., ABCDE1234F)'
                }
              })}
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.panNumber ? 'border-red-500' : 'border-gray-300'
              }`}
              placeholder="Enter PAN number"
              maxLength={10}
            />
            {errors.panNumber && (
              <p className="mt-1 text-sm text-red-600">{errors.panNumber.message}</p>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
          {/* ABHA ID */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              ABHA ID (Health ID)
            </label>
            <input
              type="text"
              {...register('abhaId')}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter ABHA ID"
            />
          </div>

          {/* Ration Card Number */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Ration Card Number
            </label>
            <input
              type="text"
              {...register('rationCardNumber')}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter ration card number"
            />
          </div>
        </div>
      </div>

      {/* Registration Details */}
      <div className="border-t pt-6">
        <h4 className="text-md font-semibold text-gray-900 mb-4">Registration Details</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Registration Type */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Registration Type *
            </label>
            <select
              {...register('registrationType', {
                required: 'Registration type is required'
              })}
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.registrationType ? 'border-red-500' : 'border-gray-300'
              }`}
            >
              <option value="">Select Registration Type</option>
              <option value="standard">Standard Registration</option>
            </select>
            {errors.registrationType && (
              <p className="mt-1 text-sm text-red-600">{errors.registrationType.message}</p>
            )}
          </div>

          {/* Registration Source */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Registration Source *
            </label>
            <select
              {...register('registrationSource', {
                required: 'Registration source is required'
              })}
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.registrationSource ? 'border-red-500' : 'border-gray-300'
              }`}
            >
              <option value="">Select Source</option>
              <option value="walk_in">Walk-in</option>
              <option value="referral">Referral</option>
              <option value="online">Online</option>
            </select>
            {errors.registrationSource && (
              <p className="mt-1 text-sm text-red-600">{errors.registrationSource.message}</p>
            )}
          </div>
        </div>

        {/* Referred By */}
        <div className="mt-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Referred By
          </label>
          <input
            type="text"
            {...register('referredBy')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter referring doctor or facility name"
          />
        </div>
      </div>
    </div>
  );
};

export default ContactInformationStep; 