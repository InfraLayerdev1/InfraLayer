// Manual mock factory for axios - plain functions to avoid jest.fn() circular issues
export function createAxiosMock() {
  const interceptors = {
    request: { use: () => {} },
    response: { use: () => {} }
  };

  const mockInstance = {
    interceptors,
    post: () => Promise.resolve({ data: {} }),
    get: () => Promise.resolve({ data: {} }),
    request: () => Promise.resolve({ data: {} }),
    defaults: {
      headers: {
        common: {}
      }
    }
  };
  return mockInstance;
}

export default {
  create: createAxiosMock
};