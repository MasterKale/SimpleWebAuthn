const rootConfig = require('../../jest.config');

module.exports = {
  ...rootConfig,
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts'],
};
