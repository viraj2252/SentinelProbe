import { createTheme } from '@mui/material/styles';

// Create a theme instance with dark mode suitable for a security dashboard
const theme = createTheme({
    palette: {
        mode: 'dark',
        primary: {
            main: '#2196f3', // Blue
            light: '#64b5f6',
            dark: '#1976d2',
            contrastText: '#fff',
        },
        secondary: {
            main: '#f50057', // Pink
            light: '#ff4081',
            dark: '#c51162',
            contrastText: '#fff',
        },
        error: {
            main: '#f44336', // Red
            light: '#e57373',
            dark: '#d32f2f',
            contrastText: '#fff',
        },
        warning: {
            main: '#ff9800', // Orange
            light: '#ffb74d',
            dark: '#f57c00',
            contrastText: 'rgba(0, 0, 0, 0.87)',
        },
        info: {
            main: '#2196f3', // Blue
            light: '#64b5f6',
            dark: '#1976d2',
            contrastText: '#fff',
        },
        success: {
            main: '#4caf50', // Green
            light: '#81c784',
            dark: '#388e3c',
            contrastText: 'rgba(0, 0, 0, 0.87)',
        },
        background: {
            default: '#121212',
            paper: '#1e1e1e',
        },
        text: {
            primary: '#fff',
            secondary: 'rgba(255, 255, 255, 0.7)',
            disabled: 'rgba(255, 255, 255, 0.5)',
        },
    },
    typography: {
        fontFamily: [
            '-apple-system',
            'BlinkMacSystemFont',
            '"Segoe UI"',
            'Roboto',
            '"Helvetica Neue"',
            'Arial',
            'sans-serif',
            '"Apple Color Emoji"',
            '"Segoe UI Emoji"',
            '"Segoe UI Symbol"',
        ].join(','),
        h1: {
            fontSize: '2.5rem',
            fontWeight: 500,
        },
        h2: {
            fontSize: '2rem',
            fontWeight: 500,
        },
        h3: {
            fontSize: '1.75rem',
            fontWeight: 500,
        },
        h4: {
            fontSize: '1.5rem',
            fontWeight: 500,
        },
        h5: {
            fontSize: '1.25rem',
            fontWeight: 500,
        },
        h6: {
            fontSize: '1rem',
            fontWeight: 500,
        },
    },
    components: {
        MuiButton: {
            styleOverrides: {
                root: {
                    borderRadius: 4,
                    textTransform: 'none',
                    fontWeight: 500,
                },
            },
        },
        MuiAppBar: {
            styleOverrides: {
                root: {
                    boxShadow: 'none',
                },
            },
        },
        MuiDrawer: {
            styleOverrides: {
                paper: {
                    backgroundColor: '#1e1e1e',
                },
            },
        },
        MuiCard: {
            styleOverrides: {
                root: {
                    borderRadius: 8,
                    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
                },
            },
        },
    },
});

export default theme;
