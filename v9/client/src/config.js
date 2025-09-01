
export const config = {
  serverURL: process.env.SERVER_URL || 'ws://localhost:8080/ws',
  clientHTTPPort: parseInt(process.env.CLIENT_HTTP_PORT || '9090', 10),
  licenseKey: process.env.CLIENT_KEY || '', // if empty, show UI
  version: '1.0.0',
};
