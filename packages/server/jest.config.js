module.exports = {
  preset: 'ts-jest',
  collectCoverageFrom: ['<rootDir>/src/**/*.{js,ts}'],
  coverageDirectory: 'coverage',
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts'],
};
