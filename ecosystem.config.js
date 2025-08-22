module.exports = {
  apps: [{
    name: 'mythiru.com',
    script: 'server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'development',
      TZ: 'America/New_York'
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000, // This can be overridden by the .env file
      TZ: 'America/New_York'
    }
  }]
};