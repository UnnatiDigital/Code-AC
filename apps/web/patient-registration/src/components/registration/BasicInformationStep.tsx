import React from 'react';
import { useFormContext } from 'react-hook-form';
import { RegistrationFormData } from '../../types/patient';

const BasicInformationStep: React.FC = () => {
  const { register, formState: { errors }, watch, setValue } = useFormContext<RegistrationFormData>();
  const dateOfBirth = watch('dateOfBirth');

  // Calculate age from date of birth
  React.useEffect(() => {
    if (dateOfBirth) {
      const today = new Date();
      const birthDate = new Date(dateOfBirth);
      const age = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();
      
      if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
        setValue('age', age - 1);
      } else {
        setValue('age', age);
      }
    }
  }, [dateOfBirth, setValue]);

  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h3 className="text-lg font-semibold text-gray-900">Basic Information</h3>
        <p className="text-sm text-gray-600">Enter the patient's personal details</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* First Name */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            First Name *
          </label>
          <input
            type="text"
            {...register('firstName', {
              required: 'First name is required',
              minLength: { value: 2, message: 'First name must be at least 2 characters' },
              maxLength: { value: 50, message: 'First name must be less than 50 characters' },
              pattern: {
                value: /^[a-zA-Z\u00C0-\u017F\s]+$/,
                message: 'First name can only contain letters and spaces'
              }
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.firstName ? 'border-red-500' : 'border-gray-300'
            }`}
            placeholder="Enter first name"
          />
          {errors.firstName && (
            <p className="mt-1 text-sm text-red-600">{errors.firstName.message}</p>
          )}
        </div>

        {/* Middle Name */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Middle Name
          </label>
          <input
            type="text"
            {...register('middleName', {
              maxLength: { value: 50, message: 'Middle name must be less than 50 characters' },
              pattern: {
                value: /^[a-zA-Z\u00C0-\u017F\s]*$/,
                message: 'Middle name can only contain letters and spaces'
              }
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.middleName ? 'border-red-500' : 'border-gray-300'
            }`}
            placeholder="Enter middle name"
          />
          {errors.middleName && (
            <p className="mt-1 text-sm text-red-600">{errors.middleName.message}</p>
          )}
        </div>

        {/* Last Name */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Last Name
          </label>
          <input
            type="text"
            {...register('lastName', {
              maxLength: { value: 50, message: 'Last name must be less than 50 characters' },
              pattern: {
                value: /^[a-zA-Z\u00C0-\u017F\s]*$/,
                message: 'Last name can only contain letters and spaces'
              }
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.lastName ? 'border-red-500' : 'border-gray-300'
            }`}
            placeholder="Enter last name"
          />
          {errors.lastName && (
            <p className="mt-1 text-sm text-red-600">{errors.lastName.message}</p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Date of Birth */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Date of Birth *
          </label>
          <input
            type="date"
            {...register('dateOfBirth', {
              required: 'Date of birth is required',
              validate: (value) => {
                if (!value) return true;
                const birthDate = new Date(value);
                const today = new Date();
                if (birthDate > today) {
                  return 'Date of birth cannot be in the future';
                }
                const age = today.getFullYear() - birthDate.getFullYear();
                if (age > 150) {
                  return 'Please enter a valid date of birth';
                }
                return true;
              }
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.dateOfBirth ? 'border-red-500' : 'border-gray-300'
            }`}
          />
          {errors.dateOfBirth && (
            <p className="mt-1 text-sm text-red-600">{errors.dateOfBirth.message}</p>
          )}
        </div>

        {/* Age (Auto-calculated) */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Age
          </label>
          <input
            type="number"
            {...register('age', {
              min: { value: 0, message: 'Age must be positive' },
              max: { value: 150, message: 'Age must be reasonable' }
            })}
            readOnly
            className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50"
            placeholder="Auto-calculated"
          />
        </div>

        {/* Gender */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Gender *
          </label>
          <select
            {...register('gender', {
              required: 'Gender is required'
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.gender ? 'border-red-500' : 'border-gray-300'
            }`}
          >
            <option value="">Select Gender</option>
            <option value="male">Male</option>
            <option value="female">Female</option>
            <option value="other">Other</option>
            <option value="prefer_not_to_say">Prefer not to say</option>
          </select>
          {errors.gender && (
            <p className="mt-1 text-sm text-red-600">{errors.gender.message}</p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Blood Group */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Blood Group
          </label>
          <select
            {...register('bloodGroup')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">Select Blood Group</option>
            <option value="A+">A+</option>
            <option value="A-">A-</option>
            <option value="B+">B+</option>
            <option value="B-">B-</option>
            <option value="AB+">AB+</option>
            <option value="AB-">AB-</option>
            <option value="O+">O+</option>
            <option value="O-">O-</option>
          </select>
        </div>

        {/* RH Factor */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            RH Factor
          </label>
          <select
            {...register('rhFactor')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">Select RH Factor</option>
            <option value="positive">Positive</option>
            <option value="negative">Negative</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Marital Status */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Marital Status
          </label>
          <select
            {...register('maritalStatus')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">Select Marital Status</option>
            <option value="single">Single</option>
            <option value="married">Married</option>
            <option value="divorced">Divorced</option>
            <option value="widowed">Widowed</option>
            <option value="separated">Separated</option>
          </select>
        </div>

        {/* Nationality */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Nationality
          </label>
          <input
            type="text"
            {...register('nationality')}
            defaultValue="Indian"
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter nationality"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Religion */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Religion
          </label>
          <input
            type="text"
            {...register('religion')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter religion"
          />
        </div>

        {/* Caste */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Caste
          </label>
          <input
            type="text"
            {...register('caste')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter caste"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Education */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Education
          </label>
          <input
            type="text"
            {...register('education')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter education level"
          />
        </div>

        {/* Occupation */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Occupation
          </label>
          <input
            type="text"
            {...register('occupation')}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter occupation"
          />
        </div>
      </div>

      <div>
        {/* Mother Tongue */}
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Mother Tongue
        </label>
        <input
          type="text"
          {...register('motherTongue')}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Enter mother tongue"
        />
      </div>
    </div>
  );
};

export default BasicInformationStep; 