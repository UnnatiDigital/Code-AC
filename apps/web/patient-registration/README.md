# HMIS Patient Registration Frontend

A modern React-based frontend application for the Healthcare Management Information System (HMIS) Core Platform.

## Features

- **Multi-step Patient Registration**: 6-step comprehensive registration process
- **Biometric Capture**: Fingerprint and facial recognition support
- **Address Management**: Multi-address support with PIN code auto-population
- **Medical Information**: Allergy tracking and medical history management
- **Patient Search**: Advanced search with multiple criteria
- **Dashboard**: Comprehensive statistics and overview
- **Responsive Design**: Mobile-first approach with Tailwind CSS
- **TypeScript**: Full type safety and IntelliSense support

## Tech Stack

- **Framework**: React 18.2.0 with TypeScript 4.9.0
- **Routing**: React Router DOM 6.8.0
- **State Management**: React Query 3.39.0 (TanStack Query)
- **Form Management**: React Hook Form 7.43.0
- **Styling**: Tailwind CSS 3.2.0 with PostCSS and Autoprefixer
- **UI Components**: Custom components with Heroicons
- **Notifications**: React Hot Toast 2.4.0
- **HTTP Client**: Axios with interceptors
- **Build Tool**: React Scripts 5.0.1

## Prerequisites

- Node.js 18+ 
- npm 8+ or yarn 1.22+
- Docker (for containerized deployment)

## Installation

### Local Development

1. **Clone the repository**
   ```bash
   cd apps/web/patient-registration
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   Create a `.env` file in the root directory:
   ```bash
   # API Configuration
   REACT_APP_API_URL=http://localhost:8082/api
   
   # Environment
   REACT_APP_ENV=development
   NODE_ENV=development
   
   # Feature Flags
   REACT_APP_ENABLE_BIOMETRICS=true
   REACT_APP_ENABLE_MULTI_LANGUAGE=true
   REACT_APP_ENABLE_INSURANCE=true
   ```

4. **Start development server**
   ```bash
   npm start
   ```

   The application will be available at `http://localhost:3000`

### Docker Deployment

1. **Build the Docker image**
   ```bash
   docker build -t hmis-frontend .
   ```

2. **Run the container**
   ```bash
   docker run -p 3000:3000 hmis-frontend
   ```

3. **Using Docker Compose**
   ```bash
   docker-compose up hmis-frontend
   ```

## Project Structure

```
src/
├── components/           # Reusable UI components
│   ├── Layout.tsx       # Main layout with navigation
│   └── registration/    # Registration form components
│       ├── BasicInformationStep.tsx
│       ├── ContactInformationStep.tsx
│       ├── AddressInformationStep.tsx
│       ├── MedicalInformationStep.tsx
│       ├── BiometricCaptureStep.tsx
│       ├── ConsentReviewStep.tsx
│       └── MultiStepRegistrationForm.tsx
├── pages/               # Page components
│   ├── Dashboard.tsx    # Main dashboard
│   ├── PatientRegistration.tsx
│   ├── PatientSearch.tsx
│   ├── PatientDetails.tsx
│   └── Settings.tsx
├── services/            # API services
│   └── api.ts          # Main API service
├── types/               # TypeScript type definitions
│   └── patient.ts      # Patient-related types
├── App.tsx             # Main application component
├── index.tsx           # Application entry point
└── index.css           # Global styles and Tailwind imports
```

## Available Scripts

- `npm start` - Start development server
- `npm run build` - Build for production
- `npm test` - Run tests
- `npm run eject` - Eject from Create React App

## Configuration

### Tailwind CSS

The application uses Tailwind CSS with custom configuration:

- **Custom Colors**: Primary, success, warning, danger, and emergency color schemes
- **Custom Animations**: Fade-in, slide-up, slide-down animations
- **Custom Shadows**: Soft, medium, and strong shadow variants
- **Forms Plugin**: Enhanced form styling with @tailwindcss/forms

### TypeScript

- **Path Aliases**: Configured for clean imports (`@/components/*`, `@/services/*`, etc.)
- **Strict Mode**: Enabled for better type safety
- **JSX**: React 17+ JSX transform

## API Integration

The frontend integrates with the HMIS Core backend API:

- **Base URL**: Configurable via `REACT_APP_API_URL` environment variable
- **Authentication**: JWT token-based authentication
- **Error Handling**: Comprehensive error handling with user-friendly messages
- **Interceptors**: Request/response interceptors for authentication and error handling

### Key API Endpoints

- `POST /api/patients/register` - Patient registration
- `GET /api/patients/:id` - Get patient by ID
- `POST /api/patients/search` - Search patients
- `GET /api/dashboard` - Dashboard data
- `POST /api/patients/check-duplicate` - Duplicate patient check

## Features in Detail

### 1. Multi-step Registration Form

The registration process is divided into 6 logical steps:

1. **Basic Information**: Name, DOB, gender, blood group
2. **Contact & ID**: Mobile, email, emergency contacts, documents
3. **Address**: Multiple addresses with PIN code validation
4. **Medical Info**: Allergies, medical history, medications
5. **Biometric Capture**: Fingerprint and facial recognition
6. **Consent & Review**: Final review and consent collection

### 2. Patient Search

- **Multi-criteria Search**: Search by name, mobile, UHID, Aadhaar, etc.
- **Advanced Filters**: Age, gender, blood group, location
- **Pagination**: Efficient handling of large result sets
- **Export**: Data export capabilities

### 3. Dashboard

- **Statistics**: Patient counts, registrations, demographics
- **Recent Activity**: Latest registrations and updates
- **Quick Actions**: Quick access to common functions
- **Charts**: Visual representation of data

## Development Guidelines

### Code Style

- Use TypeScript for all new code
- Follow React functional component patterns
- Use React Hook Form for form management
- Implement proper error boundaries
- Write meaningful component and function names

### Component Structure

- Keep components small and focused
- Use proper prop typing with TypeScript interfaces
- Implement proper error handling
- Use React Query for data fetching and caching

### State Management

- Use React Query for server state
- Use React hooks for local state
- Minimize prop drilling with proper component composition
- Use context for global state when necessary

## Testing

### Running Tests

```bash
npm test
```

### Test Coverage

```bash
npm test -- --coverage --watchAll=false
```

## Building for Production

### Development Build

```bash
npm run build
```

### Production Build

```bash
NODE_ENV=production npm run build
```

## Deployment

### Docker Compose

The application is configured to run with Docker Compose:

```yaml
hmis-frontend:
  build:
    context: ./apps/web/patient-registration
    dockerfile: Dockerfile
  ports:
    - "3000:3000"
  environment:
    - REACT_APP_API_URL=http://localhost:8082/api
    - REACT_APP_ENV=production
    - NODE_ENV=production
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REACT_APP_API_URL` | Backend API URL | `http://localhost:8082/api` |
| `REACT_APP_ENV` | Environment name | `development` |
| `NODE_ENV` | Node environment | `development` |

## Troubleshooting

### Common Issues

1. **Port 3000 already in use**
   ```bash
   # Kill the process using port 3000
   lsof -ti:3000 | xargs kill -9
   ```

2. **Build errors**
   ```bash
   # Clear node_modules and reinstall
   rm -rf node_modules package-lock.json
   npm install
   ```

3. **TypeScript errors**
   ```bash
   # Check TypeScript configuration
   npx tsc --noEmit
   ```

### Performance Issues

- Use React.memo for expensive components
- Implement proper loading states
- Use React Query's caching effectively
- Optimize bundle size with code splitting

## Contributing

1. Follow the established code style
2. Write meaningful commit messages
3. Test your changes thoroughly
4. Update documentation as needed

## License

This project is part of the HMIS Core Platform and follows the same licensing terms.

## Support

For support and questions:
- Check the project documentation
- Review existing issues
- Create a new issue with detailed information
