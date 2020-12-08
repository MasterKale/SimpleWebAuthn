import { assertIO, verifyAssertIO, attestIO, verifyAttestIO } from './Adapter';

export default class EmptyAdapter {
  key = 'EmptyAdapter';

  assert(response: assertIO): assertIO {
    return response;
  }

  verifyAssert(request: verifyAssertIO): verifyAssertIO {
    return request;
  }

  attest(response: attestIO): attestIO {
    return response;
  }

  verifyAttest(request: verifyAttestIO): verifyAttestIO {
    return request;
  }
}
