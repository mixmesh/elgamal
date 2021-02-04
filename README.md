# ElGamal encryption

A library which performs ElGamal encryption.

## Files

<dl>
  <dt>./src/elgamal.erl</dt>
  <dd>Multiplicative and additive ElGamal encryption</dd>
  <dt>./test/unit_test_elgamal.erl</dt>
  <dd>Unit test for the elgamal module</dd>
  <dt>./test/unit_test_belgamal.erl</dt>
  <dd>Unit test for the belgamal module</dd>
</dl>

## Testing

`make runtest` runs all tests, i.e.

`$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh-do-nothing.conf test/`

Tests can be run individually as well:

`$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh-do-nothing.conf elgamal`
