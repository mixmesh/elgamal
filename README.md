# ElGamal encryption

A library which performs ElGamal encryption.

## Files

<dl>
  <dt>./src/elgamal.erl</dt>
  <dd>Multiplicative and additive ElGamal encryption</dd>
  <dt>./src/belgamal.erl</dt>
  <dd>Binary marshalling of results produced by the elgamal module</dd>
  <dt>./test/unit_test_elgamal.erl</dt>
  <dd>Unit test for the elgamal module</dd>
  <dt>./test/unit_test_belgamal.erl</dt>
  <dd>Unit test for the belgamal module</dd>
</dl>

## Testing

`make runtest` runs all tests, i.e.

`$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete-do-nothing.conf test/`

Tests can be run individually as well:

```
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete-do-nothing.conf elgamal
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete-do-nothing.conf belgamal
```
