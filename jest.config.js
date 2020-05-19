module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  'moduleNameMapper': {
    '@helpers/(.*)': '<rootDir>/src/helpers/$1',
    '@types': '<rootDir>/src/types',
  },
};
