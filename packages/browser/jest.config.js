module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: './',
  collectCoverageFrom: [
    'src/**/*.{js,ts}',
  ],
  coverageDirectory: 'coverage',
  setupFilesAfterEnv: [
    './src/setupTests.ts',
  ],
  moduleNameMapper: {
    '@helpers/(.*)': './src/helpers/$1',
    '@libTypes': './src/types',
  },
};
