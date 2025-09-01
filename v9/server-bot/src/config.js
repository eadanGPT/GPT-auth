
export const config = {
  serverURL: process.env.SERVER_URL || 'ws://localhost:8080/ws',
  botHTTPPort: parseInt(process.env.BOT_HTTP_PORT || '9191', 10),
  licenseKey: process.env.SERVER_BOT_LICENSE_KEY || process.env.CLIENT_KEY || '',
  mcHost: process.env.MC_HOST || 'localhost',
  mcPort: parseInt(process.env.MC_PORT || '25565', 10),
  mcVersion: process.env.MC_VERSION || '1.20.4',
  botName: process.env.BOT_NAME || 'ServerSideBot'
};
