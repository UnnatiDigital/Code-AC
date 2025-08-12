import React, { useState, useEffect } from 'react';
import { useFormContext } from 'react-hook-form';
import { RegistrationFormData, PatientAllergy } from '../../types/patient';

const MedicalInformationStep: React.FC = () => {
  const { register, formState: { errors }, watch, setValue } = useFormContext<RegistrationFormData>();
  const [allergies, setAllergies] = useState<PatientAllergy[]>([]);
  const [showAllergyForm, setShowAllergyForm] = useState(false);
  const [newAllergy, setNewAllergy] = useState<Partial<PatientAllergy>>({});

  const bloodGroup = watch('bloodGroup');
  const rhFactor = watch('rhFactor');

  // Common allergies for quick selection
  const commonAllergies = [
    'Penicillin', 'Amoxicillin', 'Aspirin', 'Ibuprofen', 'Sulfa Drugs',
    'Latex', 'Peanuts', 'Tree Nuts', 'Shellfish', 'Eggs', 'Milk',
    'Soy', 'Wheat', 'Dairy', 'Dust', 'Pollen', 'Pet Dander'
  ];

  const addAllergy = () => {
    if (newAllergy.name && newAllergy.severity) {
      const allergy: PatientAllergy = {
        id: Date.now().toString(),
        name: newAllergy.name,
        severity: newAllergy.severity as 'mild' | 'severe',
        reaction: newAllergy.reaction || '',
        notes: newAllergy.notes || ''
      };
      const updatedAllergies = [...allergies, allergy];
      setAllergies(updatedAllergies);
      setValue('allergies', updatedAllergies);
      setNewAllergy({});
      setShowAllergyForm(false);
    }
  };

  const removeAllergy = (id: string) => {
    const updatedAllergies = allergies.filter(allergy => allergy.id !== id);
    setAllergies(updatedAllergies);
    setValue('allergies', updatedAllergies);
  };

  const selectCommonAllergy = (allergyName: string) => {
    setNewAllergy({ name: allergyName });
    setShowAllergyForm(true);
  };

  return (
    <div className="space-y-6">
      <div className="border-b border-gray-200 pb-4">
        <h3 className="text-lg font-semibold text-gray-900">Medical Information</h3>
        <p className="text-sm text-gray-600">Enter the patient's medical details and allergies</p>
      </div>

      {/* Blood Group Display with RH Factor */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Blood Group
          </label>
          <div className={`p-3 border rounded-md ${
            bloodGroup?.includes('-') ? 'border-red-300 bg-red-50' : 'border-gray-300 bg-gray-50'
          }`}>
            <span className={`font-semibold ${
              bloodGroup?.includes('-') ? 'text-red-700' : 'text-gray-700'
            }`}>
              {bloodGroup || 'Not specified'} {rhFactor && `(${rhFactor})`}
            </span>
            {bloodGroup?.includes('-') && (
              <p className="text-sm text-red-600 mt-1">⚠️ Rh-negative blood group requires special attention</p>
            )}
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Height (cm)
          </label>
          <input
            type="number"
            {...register('height', {
              min: { value: 50, message: 'Height must be at least 50 cm' },
              max: { value: 250, message: 'Height must be reasonable' }
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.height ? 'border-red-500' : 'border-gray-300'
            }`}
            placeholder="Enter height in cm"
          />
          {errors.height && (
            <p className="mt-1 text-sm text-red-600">{errors.height.message}</p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Weight (kg)
          </label>
          <input
            type="number"
            {...register('weight', {
              min: { value: 1, message: 'Weight must be at least 1 kg' },
              max: { value: 300, message: 'Weight must be reasonable' }
            })}
            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              errors.weight ? 'border-red-500' : 'border-gray-300'
            }`}
            placeholder="Enter weight in kg"
          />
          {errors.weight && (
            <p className="mt-1 text-sm text-red-600">{errors.weight.message}</p>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            BMI
          </label>
          <input
            type="number"
            {...register('bmi')}
            readOnly
            className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50"
            placeholder="Auto-calculated"
          />
        </div>
      </div>

      {/* Allergies Section */}
      <div className="border-t pt-6">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-md font-semibold text-gray-900">Allergies</h4>
          <button
            type="button"
            onClick={() => setShowAllergyForm(true)}
            className="px-3 py-1 bg-blue-600 text-white text-sm rounded-md hover:bg-blue-700"
          >
            + Add Allergy
          </button>
        </div>

        {/* Common Allergies Quick Selection */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Quick Select Common Allergies
          </label>
          <div className="flex flex-wrap gap-2">
            {commonAllergies.map((allergy) => (
              <button
                key={allergy}
                type="button"
                onClick={() => selectCommonAllergy(allergy)}
                className="px-3 py-1 bg-gray-100 text-gray-700 text-sm rounded-full hover:bg-gray-200 border border-gray-300"
              >
                {allergy}
              </button>
            ))}
          </div>
        </div>

        {/* Allergy Form */}
        {showAllergyForm && (
          <div className="border border-blue-200 rounded-lg p-4 bg-blue-50 mb-4">
            <h5 className="font-medium text-blue-900 mb-3">Add New Allergy</h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Allergy Name *
                </label>
                <input
                  type="text"
                  value={newAllergy.name || ''}
                  onChange={(e) => setNewAllergy({ ...newAllergy, name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Enter allergy name"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Severity *
                </label>
                <select
                  value={newAllergy.severity || ''}
                  onChange={(e) => setNewAllergy({ ...newAllergy, severity: e.target.value as 'mild' | 'severe' })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Select Severity</option>
                  <option value="mild">Mild</option>
                  <option value="severe">Severe</option>
                </select>
              </div>
            </div>
            <div className="mt-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Reaction
              </label>
              <input
                type="text"
                value={newAllergy.reaction || ''}
                onChange={(e) => setNewAllergy({ ...newAllergy, reaction: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Describe the reaction"
              />
            </div>
            <div className="mt-4">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Notes
              </label>
              <textarea
                value={newAllergy.notes || ''}
                onChange={(e) => setNewAllergy({ ...newAllergy, notes: e.target.value })}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Additional notes"
              />
            </div>
            <div className="flex justify-end space-x-2 mt-4">
              <button
                type="button"
                onClick={() => {
                  setShowAllergyForm(false);
                  setNewAllergy({});
                }}
                className="px-3 py-1 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={addAllergy}
                className="px-3 py-1 bg-blue-600 text-white rounded-md hover:bg-blue-700"
              >
                Add Allergy
              </button>
            </div>
          </div>
        )}

        {/* Allergies List */}
        {allergies.length > 0 ? (
          <div className="space-y-3">
            {allergies.map((allergy) => (
              <div key={allergy.id} className="flex items-center justify-between p-3 border border-gray-200 rounded-md">
                <div className="flex items-center space-x-3">
                  <span className="text-yellow-600 text-lg">⚠️</span>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-medium text-gray-900">{allergy.name}</span>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        allergy.severity === 'severe' 
                          ? 'bg-red-100 text-red-800' 
                          : 'bg-yellow-100 text-yellow-800'
                      }`}>
                        {allergy.severity.toUpperCase()}
                      </span>
                    </div>
                    {allergy.reaction && (
                      <p className="text-sm text-gray-600">Reaction: {allergy.reaction}</p>
                    )}
                    {allergy.notes && (
                      <p className="text-sm text-gray-500">Notes: {allergy.notes}</p>
                    )}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => removeAllergy(allergy.id)}
                  className="text-red-600 hover:text-red-800"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-gray-500">
            <p>No allergies recorded</p>
            <p className="text-sm">Click "Add Allergy" to record any known allergies</p>
          </div>
        )}
      </div>

      {/* Medical History */}
      <div className="border-t pt-6">
        <h4 className="text-md font-semibold text-gray-900 mb-4">Medical History</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Chronic Conditions
            </label>
            <textarea
              {...register('chronicConditions')}
              rows={3}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="List any chronic medical conditions"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Current Medications
            </label>
            <textarea
              {...register('currentMedications')}
              rows={3}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="List current medications and dosages"
            />
          </div>
        </div>

        <div className="mt-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Family Medical History
          </label>
          <textarea
            {...register('familyMedicalHistory')}
            rows={3}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Relevant family medical history"
          />
        </div>
      </div>

      {/* Lifestyle Information */}
      <div className="border-t pt-6">
        <h4 className="text-md font-semibold text-gray-900 mb-4">Lifestyle Information</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Smoking Status
            </label>
            <select
              {...register('smokingStatus')}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select Status</option>
              <option value="never">Never Smoked</option>
              <option value="former">Former Smoker</option>
              <option value="current">Current Smoker</option>
              <option value="passive">Passive Smoker</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Alcohol Consumption
            </label>
            <select
              {...register('alcoholConsumption')}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select Status</option>
              <option value="never">Never</option>
              <option value="occasional">Occasional</option>
              <option value="moderate">Moderate</option>
              <option value="heavy">Heavy</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Physical Activity
            </label>
            <select
              {...register('physicalActivity')}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select Level</option>
              <option value="sedentary">Sedentary</option>
              <option value="light">Light</option>
              <option value="moderate">Moderate</option>
              <option value="active">Active</option>
              <option value="very_active">Very Active</option>
            </select>
          </div>
        </div>
      </div>

      {/* Allergy Warning */}
      {allergies.some(a => a.severity === 'severe') && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Severe Allergies Detected</h3>
              <div className="mt-2 text-sm text-red-700">
                <p>⚠️ This patient has severe allergies that require immediate attention and special care protocols.</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MedicalInformationStep; 