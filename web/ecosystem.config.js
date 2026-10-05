module.exports = {
  apps: [
    {
      name: "reveo-app",
      script: "server.js",
      cwd: __dirname,
      env: {
        NODE_ENV: "production"
      }
    }
  ]
};
