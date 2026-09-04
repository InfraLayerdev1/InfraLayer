// Jest setup file to mock axios before tests run
// Using jest.fn() properly to enable mockResolvedValueOnce, etc.
jest.mock('axios', () => {
  const createMockInstance = () => {
    const post = jest.fn(() => Promise.resolve({ data: {} }));
    const get = jest.fn(() => Promise.resolve({ data: {} }));
    const request = jest.fn(() => Promise.resolve({ data: {} }));

    return {
      interceptors: {
        request: { use: jest.fn() },
        response: { use: jest.fn() }
      },
      post,
      get,
      request,
      defaults: {
        headers: {
          common: {}
        }
      }
    };
  };

  const mockInstance = createMockInstance();

  return {
    create: jest.fn(() => mockInstance),
    __esModule: true,
    default: {
      create: jest.fn(() => mockInstance)
    }
  };
});