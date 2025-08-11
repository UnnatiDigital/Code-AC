import React from 'react';
import { Toaster } from 'react-hot-toast';
import MultiStepRegistrationForm from '../components/registration/MultiStepRegistrationForm';

const PatientRegistration: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50">
      <Toaster 
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#363636',
            color: '#fff',
          },
          success: {
            duration: 3000,
            iconTheme: {
              primary: '#10B981',
              secondary: '#fff',
            },
          },
          error: {
            duration: 4000,
            iconTheme: {
              primary: '#EF4444',
              secondary: '#fff',
            },
          },
        }}
      />
      <MultiStepRegistrationForm />
    </div>
  );
};

export default PatientRegistration; 