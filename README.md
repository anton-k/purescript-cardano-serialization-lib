# purescript-cardano-serialization-lib

Pursecript library for cardano frontend types for [emurgo/cardano-serialisation-lib](https://github.com/Emurgo/cardano-serialization-lib)

## How to use the library

Library ports the [CSL api](https://github.com/Emurgo/cardano-serialization-lib/blob/master/rust/pkg/cardano_serialization_lib.js.flow).
The JS classes are converted to values of record type which
define interface for a given class. The value contains both static and object
methods. For object methods the self argument always goes first.

For example if we want to create `BigNum` from string in JS we can write:

```js
Csl.BigNum.from_str("100200");
```

In purescript it is called on the value `bigInt` which provides the function:

```purescript
Csl.bigNum.fromStr "100200"
```

So you can apply all the functions from emurgo/CSL. Just read the original API
and see translation conventions to use it in purescript.

## Used translation conventions

* snake case becomes camel case: `from_str` turns to `fromStr`

* For class, function and method names long words are substituted with shorter ones:

  * `Transaction` to `Tx`
  * `Output` to `Out`
  * `Input` to `In`
  * `ValueJSON` to `ValueJs` etc for all types




