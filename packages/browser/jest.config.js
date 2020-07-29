const rootConfig = require('../../jest.config');

module.exports = {
  ...rootConfig,
  testEnvironment: '<rootDir>/jest-environment.js',
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts'],
};
