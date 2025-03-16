# SentinelProbe Frontend

This is the frontend application for SentinelProbe, an AI-powered penetration testing system.

## Technology Stack

- React 18
- TypeScript
- Material-UI
- React Router
- Axios
- D3.js for data visualization

## Getting Started

### Prerequisites

- Node.js 16+
- npm 8+

### Installation

1. Clone the repository
2. Navigate to the frontend directory
3. Install dependencies:

```bash
npm install
```

### Development

To start the development server:

```bash
npm run dev
```

This will start the development server at [http://localhost:5173](http://localhost:5173).

### Building for Production

To build the application for production:

```bash
npm run build
```

The build artifacts will be stored in the `dist/` directory.

### Testing

To run the tests:

```bash
npm run test
```

## Project Structure

- `src/components/` - Reusable UI components
- `src/pages/` - Page components
- `src/services/` - API services
- `src/utils/` - Utility functions
- `src/hooks/` - Custom React hooks
- `src/contexts/` - React context providers
- `src/types/` - TypeScript type definitions
- `src/assets/` - Static assets

## Features

- Dashboard with vulnerability summary
- Scan management
- Vulnerability reporting
- Security test configuration
- User authentication and authorization

## Contributing

Please read the contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
