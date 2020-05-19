module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  collectCoverageFrom: [
    'src/**/*.{js,ts}',
  ],
  coverageDirectory: 'coverage',
  setupFilesAfterEnv: [
    '<rootDir>/src/setupTests.ts',
  ],
  moduleNameMapper: {
    '@helpers/(.*)': '<rootDir>/src/helpers/$1',
    '@types': '<rootDir>/src/types',
  },
};
