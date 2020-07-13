const rootConfig = require('../../jest.config');

module.exports = {
  ...rootConfig,
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts'],
};
