# 🏥 HMIS Core Platform

**Healthcare Management Information System**

A comprehensive, modern healthcare information management system built with React frontend and Go backend, featuring biometric authentication, multi-language support, and enterprise-grade security.

[![Go Version](https://img.shields.io/badge/Go-1.23.0-blue.svg)](https://golang.org/)
[![React Version](https://img.shields.io/badge/React-18.2.0-blue.svg)](https://reactjs.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com/)

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [API Documentation](#-api-documentation)
- [Development](#-development)
- [Deployment](#-deployment)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🧑‍⚕️ Patient Management
- **Multi-step Registration**: 6-step comprehensive patient registration process
- **Unique Health ID (UHID)**: Auto-generated unique patient identifiers
- **Duplicate Detection**: Advanced algorithms to prevent duplicate registrations
- **Patient Search**: Multi-criteria search with pagination
- **CRUD Operations**: Full patient lifecycle management

### 🔐 Biometric Authentication
- **Fingerprint Recognition**: NFIQ 2.0 compliant processing
- **Facial Recognition**: ICAO compliant with liveness detection
- **Iris Recognition**: High-accuracy iris scanning
- **Quality Assessment**: Automated quality scoring
- **Multi-modal Support**: Combined biometric authentication

### 🏠 Address Management
- **Multi-address Support**: Permanent, temporary, and correspondence addresses
- **PIN Code Integration**: Indian postal code auto-population
- **Geographic Hierarchy**: State, district, city management
- **Address Validation**: Comprehensive verification system

### 💊 Medical Information
- **Allergy Management**: Comprehensive tracking with severity assessment
- **Medical History**: Family and personal history recording
- **Insurance Policies**: Multiple provider support
- **Document Management**: Aadhaar, PAN, ABHA ID integration

### 🌐 Multi-language Support
- **10 Indian Languages**: Hindi, Tamil, Bengali, Gujarati, Marathi, Telugu, Kannada, Malayalam, Punjabi
- **Translation Services**: Google, Azure, AWS integration
- **Localization**: Culture-specific formatting

## 🛠️ Tech Stack

### Frontend
- **React 18.2.0** with TypeScript 4.9.0
- **Tailwind CSS 3.2.0** for styling
- **React Query** for state management
- **React Hook Form** for form handling
- **React Router** for navigation

### Backend
- **Go 1.23.0** with Gin framework
- **PostgreSQL 15** (SQLite for development)
- **Redis 7** for caching
- **JWT** authentication with bcrypt
- **SQLx** for database operations

### Infrastructure
- **Docker** with Docker Compose
- **Health Checks** for all services
- **Prometheus** metrics and **Jaeger** tracing
- **Kafka** for message queuing

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Go 1.23+ (for local development)
- Node.js 18+ (for frontend development)

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/hmis-core-platform.git
cd hmis-core-platform
```

### 2. Start with Docker (Recommended)
```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### 3. Access the Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8082
- **Health Check**: http://localhost:8082/health
- **API Status**: http://localhost:8082/api/status

### 4. Database Setup
```bash
# Access PostgreSQL
docker exec -it hmis-postgres psql -U postgres -d hmis_core

# Run migrations (automatic on startup)
# Check migration status
docker exec -it hmis-core ./hmis-core migrate status
```

## 📁 Project Structure

```
hmis-core-platform/
├── apps/
│   └── web/
│       └── patient-registration/     # React frontend app
│           ├── src/
│           │   ├── components/       # UI components
│           │   ├── pages/           # Page components
│           │   ├── services/        # API services
│           │   └── types/           # TypeScript types
│           └── package.json
├── core/                            # Go backend
│   ├── cmd/                         # Application entry points
│   ├── internal/                    # Private application code
│   │   ├── controllers/            # HTTP controllers
│   │   ├── services/               # Business logic
│   │   ├── repositories/           # Data access layer
│   │   ├── models/                 # Data models
│   │   └── middleware/             # HTTP middleware
│   ├── config/                      # Configuration files
│   ├── migrations/                  # Database migrations
│   └── go.mod
├── docker-compose.yml               # Docker services
└── README.md
```

## 🔌 API Documentation

### Base URL
```
http://localhost:8082/api
```

### Authentication
```bash
# Get JWT token
POST /auth/login
{
  "username": "admin",
  "password": "password"
}
```

### Patient Endpoints
```bash
# Register new patient
POST /patients/register

# Get patient by ID
GET /patients/{id}

# Search patients
POST /patients/search

# Update patient
PUT /patients/{id}

# Delete patient
DELETE /patients/{id}
```

### Biometric Endpoints
```bash
# Register biometric data
POST /patients/{id}/biometric

# Search by biometric
POST /patients/search/biometric
```

### Health & Status
```bash
# Health check
GET /health

# API status
GET /api/status
```

For complete API documentation, see [API_REFERENCE.md](docs/API_REFERENCE.md)

## 🛠️ Development

### Backend Development

#### Prerequisites
```bash
# Install Go 1.23+
go version

# Install dependencies
cd core
go mod download
```

#### Local Development
```bash
# Run with hot reload
go run cmd/main.go

# Run tests
go test ./...

# Run with specific config
go run cmd/main.go --config=./config/config.dev.yaml
```

#### Database Migrations
```bash
# Create new migration
go run cmd/migrate/main.go create migration_name

# Run migrations
go run cmd/migrate/main.go up

# Rollback migrations
go run cmd/migrate/main.go down
```

### Frontend Development

#### Prerequisites
```bash
# Install Node.js 18+
node --version
npm --version
```

#### Local Development
```bash
cd apps/web/patient-registration

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build

# Run tests
npm test
```

#### Environment Variables
Create `.env.local` file:
```env
REACT_APP_API_URL=http://localhost:8082/api
REACT_APP_ENV=development
```

## 🚀 Deployment

### Production Deployment

#### 1. Environment Configuration
```bash
# Copy production config
cp core/config/config.yaml core/config/config.prod.yaml

# Update production values
vim core/config/config.prod.yaml
```

#### 2. Docker Production Build
```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Start production services
docker-compose -f docker-compose.prod.yml up -d
```

#### 3. SSL/HTTPS Setup
```bash
# Update production config
ssl:
  enabled: true
  cert_file: "/etc/ssl/certs/hmis.crt"
  key_file: "/etc/ssl/private/hmis.key"
```

### Monitoring & Observability

#### Prometheus Metrics
```bash
# Access metrics
curl http://localhost:9090/metrics

# Configure Grafana dashboard
# Import dashboard from grafana/dashboards/
```

#### Health Checks
```bash
# Service health
curl http://localhost:8082/health

# Database health
curl http://localhost:8082/health/database

# Redis health
curl http://localhost:8082/health/redis
```

## 🧪 Testing

### Backend Testing
```bash
cd core

# Run all tests
go test ./...

# Run specific test
go test ./internal/services -v

# Run with coverage
go test ./... -cover

# Run integration tests
go test ./tests/integration/...
```

### Frontend Testing
```bash
cd apps/web/patient-registration

# Run tests
npm test

# Run with coverage
npm test -- --coverage

# Run E2E tests
npm run test:e2e
```

### API Testing
```bash
# Test patient registration
curl -X POST http://localhost:8082/api/patients/register \
  -H "Content-Type: application/json" \
  -d @test_data/patient_registration.json

# Test health endpoint
curl http://localhost:8082/health
```

## 🔧 Configuration

### Environment Variables
```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=root
DB_NAME=hmis_core

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT
JWT_SECRET=your-secret-key
JWT_EXPIRATION=24h

# Server
SERVER_ADDRESS=:8082
GIN_MODE=release
```

### Configuration File
```yaml
# core/config/config.yaml
app:
  name: "HMIS Core Platform"
  version: "1.0.0"
  environment: "development"

server:
  address: ":8082"
  read_timeout: 30s
  write_timeout: 30s

database:
  driver: "postgres"
  host: "localhost"
  port: "5432"
  user: "postgres"
  password: "root"
  name: "hmis_core"
```

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `go test ./...` and `npm test`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

### Code Style
- **Go**: Follow [Effective Go](https://golang.org/doc/effective_go.html)
- **React**: Follow [React Style Guide](https://github.com/airbnb/javascript/tree/master/react)
- **TypeScript**: Follow [TypeScript Style Guide](https://github.com/microsoft/TypeScript/wiki/Coding-guidelines)

### Testing Requirements
- All new features must include tests
- Maintain >80% code coverage
- Include integration tests for API endpoints
- Frontend components must have unit tests

## 📊 Performance & Monitoring

### Performance Metrics
- **Response Time**: <200ms for API calls
- **Throughput**: >1000 requests/second
- **Database**: <50ms query response time
- **Memory Usage**: <512MB per service

### Monitoring Tools
- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboard
- **Jaeger**: Distributed tracing
- **ELK Stack**: Log aggregation

### Health Checks
```bash
# Service health
curl http://localhost:8082/health

# Database connectivity
curl http://localhost:8082/health/database

# Redis connectivity
curl http://localhost:8082/health/redis

# External APIs
curl http://localhost:8082/health/external
```

## 🔒 Security

### Authentication & Authorization
- JWT-based authentication
- Role-based access control (RBAC)
- Multi-factor authentication support
- Session management

### Data Protection
- AES-256-GCM encryption
- Data masking for sensitive fields
- Comprehensive audit logging
- GDPR compliance features

### API Security
- Rate limiting and DDoS protection
- Input validation and sanitization
- CORS policy enforcement
- HTTPS/TLS encryption

## 📚 Additional Resources

### Documentation
- [API Reference](docs/API_REFERENCE.md)
- [Database Schema](docs/DATABASE_SCHEMA.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Contributing Guidelines](CONTRIBUTING.md)

### External Integrations
- [ABDM Documentation](https://abdm.gov.in/)
- [NHCX Documentation](https://nhcx.abdm.gov.in/)
- [Razorpay API](https://razorpay.com/docs/)
- [Twilio API](https://www.twilio.com/docs/)

### Healthcare Standards
- [HL7 FHIR](https://www.hl7.org/fhir/)
- [ICD-10](https://www.who.int/classifications/icd/en/)
- [SNOMED CT](https://www.snomed.org/)

## 🆘 Support

### Getting Help
- **Documentation**: Check this README and docs/ folder
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Email**: support@bmad-method.com

### Common Issues
- **Port conflicts**: Ensure ports 3000, 8082, 5432, 6379 are available
- **Database connection**: Check PostgreSQL service is running
- **CORS errors**: Verify CORS configuration in backend
- **Biometric devices**: Ensure proper device drivers are installed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **BMad-Method Team** for the innovative healthcare solutions
- **Open Source Community** for the amazing tools and libraries
- **Healthcare Professionals** for domain expertise and feedback
- **Contributors** who help improve the platform

---

**Made with ❤️ for better healthcare management**

For more information, visit [https://bmad-method.com](https://bmad-method.com)
