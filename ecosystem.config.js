module.exports = {
  apps: [{
    name: 'personal-website-admin',
    script: 'server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 3000,
      BASE_PATH: '/admin'
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      BASE_PATH: '/admin'
    }
  }]
};
