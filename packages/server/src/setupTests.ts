// Silence some console output
jest.spyOn(console, 'log').mockImplementation();
jest.spyOn(console, 'debug').mockImplementation();
jest.spyOn(console, 'error').mockImplementation();
