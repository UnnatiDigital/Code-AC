import React, { useState, useEffect } from 'react';
import { useFormContext } from 'react-hook-form';
import { RegistrationFormData } from '../../types/patient';

// PIN code to location mapping (simplified for demo)
const PIN_CODE_DATA: { [key: string]: { state: string; district: string; subDistrict: string } } = {
  '110001': { state: 'Delhi', district: 'New Delhi', subDistrict: 'Connaught Place' },
  '400001': { state: 'Maharashtra', district: 'Mumbai', subDistrict: 'Fort' },
  '700001': { state: 'West Bengal', district: 'Kolkata', subDistrict: 'BBD Bagh' },
  '600001': { state: 'Tamil Nadu', district: 'Chennai', subDistrict: 'George Town' },
  '500001': { state: 'Telangana', district: 'Hyderabad', subDistrict: 'Abids' },
  '560001': { state: 'Karnataka', district: 'Bangalore', subDistrict: 'City Market' },
  '380001': { state: 'Gujarat', district: 'Ahmedabad', subDistrict: 'Ellis Bridge' },
  '302001': { state: 'Rajasthan', district: 'Jaipur', subDistrict: 'Hawa Mahal' },
  '226001': { state: 'Uttar Pradesh', district: 'Lucknow', subDistrict: 'Hazratganj' },
  '800001': { state: 'Bihar', district: 'Patna', subDistrict: 'Gandhi Maidan' },
};

const AddressInformationStep: React.FC = () => {
  const { register, formState: { errors }, watch, setValue } = useFormContext<RegistrationFormData>();
  const [addresses, setAddresses] = useState([
    { id: 1, type: 'permanent', isPrimary: true }
  ]);

  const pinCode = watch('addresses.0.pinCode');

  // Auto-populate location data when PIN code changes
  useEffect(() => {
    if (pinCode && PIN_CODE_DATA[pinCode]) {
      const locationData = PIN_CODE_DATA[pinCode];
      setValue('addresses.0.state', locationData.state);
      setValue('addresses.0.district', locationData.district);
      setValue('addresses.0.subDistrict', locationData.subDistrict);
    }
  }, [pinCode, setValue]);

  const addAddress = () => {
    const newId = Math.max(...addresses.map(addr => addr.id)) + 1;
    setAddresses([...addresses, { id: newId, type: 'current', isPrimary: false }]);
  };

  const removeAddress = (id: number) => {
    if (addresses.length > 1) {
      setAddresses(addresses.filter(addr => addr.id !== id));
    }
  };

  const setPrimaryAddress = (id: number) => {
    setAddresses(addresses.map(addr => ({
      ...addr,
      isPrimary: addr.id === id
    })));
  };

  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h3 className="text-lg font-semibold text-gray-900">Address Information</h3>
        <p className="text-sm text-gray-600">Enter the patient's address details</p>
      </div>

      {addresses.map((address, index) => (
        <div key={address.id} className="border border-gray-200 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-md font-semibold text-gray-900">
              {address.type === 'permanent' ? 'Permanent Address' : 
               address.type === 'current' ? 'Current Address' :
               address.type === 'office' ? 'Office Address' : 'Emergency Contact Address'}
            </h4>
            <div className="flex items-center space-x-2">
              {addresses.length > 1 && (
                <button
                  type="button"
                  onClick={() => removeAddress(address.id)}
                  className="text-red-600 hover:text-red-800 text-sm"
                >
                  Remove
                </button>
              )}
              {!address.isPrimary && (
                <button
                  type="button"
                  onClick={() => setPrimaryAddress(address.id)}
                  className="text-blue-600 hover:text-blue-800 text-sm"
                >
                  Set as Primary
                </button>
              )}
              {address.isPrimary && (
                <span className="text-green-600 text-sm font-medium">Primary Address</span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Address Type */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Address Type
              </label>
              <select
                {...register(`addresses.${index}.type`)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="permanent">Permanent</option>
                <option value="current">Current (Temporary)</option>
                <option value="office">Office</option>
                <option value="emergency">Emergency Contact</option>
              </select>
            </div>

            {/* PIN Code */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                PIN Code *
              </label>
              <input
                type="text"
                {...register(`addresses.${index}.pinCode`, {
                  required: 'PIN code is required',
                  pattern: {
                    value: /^\d{6}$/,
                    message: 'PIN code must be 6 digits'
                  }
                })}
                className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                  errors.addresses?.[index]?.pinCode ? 'border-red-500' : 'border-gray-300'
                }`}
                placeholder="Enter 6-digit PIN code"
                maxLength={6}
              />
              {errors.addresses?.[index]?.pinCode && (
                <p className="mt-1 text-sm text-red-600">{errors.addresses[index]?.pinCode?.message}</p>
              )}
            </div>
          </div>

          {/* Address Line */}
          <div className="mt-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Address Line *
            </label>
            <textarea
              {...register(`addresses.${index}.address`, {
                required: 'Address is required',
                minLength: { value: 10, message: 'Address must be at least 10 characters' }
              })}
              rows={3}
              className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.addresses?.[index]?.address ? 'border-red-500' : 'border-gray-300'
              }`}
              placeholder="Enter complete address"
            />
            {errors.addresses?.[index]?.address && (
              <p className="mt-1 text-sm text-red-600">{errors.addresses[index]?.address?.message}</p>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
            {/* State */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                State *
              </label>
              <input
                type="text"
                {...register(`addresses.${index}.state`, {
                  required: 'State is required'
                })}
                className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                  errors.addresses?.[index]?.state ? 'border-red-500' : 'border-gray-300'
                }`}
                placeholder="Enter state"
              />
              {errors.addresses?.[index]?.state && (
                <p className="mt-1 text-sm text-red-600">{errors.addresses[index]?.state?.message}</p>
              )}
            </div>

            {/* District */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                District *
              </label>
              <input
                type="text"
                {...register(`addresses.${index}.district`, {
                  required: 'District is required'
                })}
                className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                  errors.addresses?.[index]?.district ? 'border-red-500' : 'border-gray-300'
                }`}
                placeholder="Enter district"
              />
              {errors.addresses?.[index]?.district && (
                <p className="mt-1 text-sm text-red-600">{errors.addresses[index]?.district?.message}</p>
              )}
            </div>

            {/* Sub District */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Sub District
              </label>
              <input
                type="text"
                {...register(`addresses.${index}.subDistrict`)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter sub district"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
            {/* City/Village */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                City/Village *
              </label>
              <input
                type="text"
                {...register(`addresses.${index}.city`, {
                  required: 'City/Village is required'
                })}
                className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                  errors.addresses?.[index]?.city ? 'border-red-500' : 'border-gray-300'
                }`}
                placeholder="Enter city or village"
              />
              {errors.addresses?.[index]?.city && (
                <p className="mt-1 text-sm text-red-600">{errors.addresses[index]?.city?.message}</p>
              )}
            </div>

            {/* Landmark */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Landmark
              </label>
              <input
                type="text"
                {...register(`addresses.${index}.landmark`)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter nearby landmark"
              />
            </div>
          </div>
        </div>
      ))}

      {/* Add Address Button */}
      <div className="flex justify-center">
        <button
          type="button"
          onClick={addAddress}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          + Add Another Address
        </button>
      </div>

      {/* Address Validation Info */}
      <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
        <div className="flex">
          <div className="flex-shrink-0">
            <svg className="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-blue-800">Address Validation</h3>
            <div className="mt-2 text-sm text-blue-700">
              <p>• PIN code will auto-populate State, District, and Sub-district</p>
              <p>• At least one address is required for registration</p>
              <p>• Primary address will be used for default communications</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AddressInformationStep; 