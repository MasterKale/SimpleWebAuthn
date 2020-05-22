module.exports = {
  preset: 'ts-jest',
  collectCoverageFrom: [
    '<rootDir>/src/**/*.{js,ts}',
  ],
  coverageDirectory: 'coverage',
  setupFilesAfterEnv: [
    '<rootDir>/src/setupTests.ts',
  ],
  moduleNameMapper: {
    '@helpers/(.*)': '<rootDir>/src/helpers/$1',
    '@libTypes': '<rootDir>/src/libTypes',
  },
};
