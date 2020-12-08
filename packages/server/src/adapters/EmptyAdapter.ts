import Adapter from './Adapter';
import { assertIO, verifyAssertIO, attestIO, verifyAttestIO } from './Adapter';

export default class EmptyAdapter extends Adapter {
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
