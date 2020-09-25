# ElGamal encryption

A library which performs ElGamal encryption.

## Modules

<dl>
  <dt>./src/elgamal.erl</dt>
  <dd>Multiplicate and additive ElGamal encryption
  <dt>./src/belgamal.erl</dt>
  <dd>Binary marshalling of results produced by the elgamal module</dd>
</dl>

## Unit testing

* ./test/unit_test_elgamal.erl
* ./test/unit_test_belgamal.erl

They can be run separately with the following commands:

```
$ ../obscrete/bin/unit_test --config ../obscrete/etc/obscrete-no-players.conf elgamal
$ ../obscrete/bin/unit_test --config ../obscrete/etc/obscrete-no-players.conf elgamal
```

or all in once with the following command:

```
$ ../obscrete/bin/unit_test --config ../obscrete/etc/obscrete-no-players.conf test/
```
