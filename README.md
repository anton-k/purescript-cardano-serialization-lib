# purescript-cardano-serialization-lib

Pursecript library for cardano frontend types for [emurgo/cardano-serialisation-lib](https://github.com/Emurgo/cardano-serialization-lib)
At the moment bindongs are only for browser version.

Cardano serialization library can be used to work with Cardano types on frontend.
We can create TX and export them to the form which can then be submitted
over wallet or API to the node.

The main ide of the library is to provide thin layer of FFI bindings to the original CSL library.
It does not try to make any abstractions beyond what is provided with CSL. 
It gives you solid foundation to build your own abstractions.

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

### How to build your code with it

To use this library you whould also add emurgo/cardano-serialization-lib-browser
as external dependency. Provide this library with your JS code package manager
and also compile the purs code with it as external dep.

See the Makefile for example how to do it. We should build with spago
and use esbuild on packaging to js code bundle where we can set up the external 
dependency on CSL:

```
> esbuild \
  ./output/Main/index.js \
  --bundle \
  --outfile=demo/src/purs.js \
  --platform=browser \
  --format=esm \
  --external:@emurgo/cardano-serialization-lib-browser
```

To add the library to your project edit `packages.dhall` (see fields `upstream` and `with` on the examples in the comments) to
include external github library. see the spago docs on how to do that.

## Used translation conventions

* snake case becomes camel case: `from_str` turns to `fromStr`

* For class, function and method names long words are substituted with shorter ones:

  * `Transaction` to `Tx`
  * `Output` to `Out`
  * `Input` to `In`
  * `ValueJSON` to `ValueJs` etc for all types

So `TransactionInput` becomes `TxIn` and `AddressJSON` becomes `AddresJs`.

## Possible issues

Code is auto generated from CSL API.
Alas for some functions it's not possible to tell is it pure
or dirty. Submit an issue if you have found an effectful function
which is declared like pure and vise versa.

See the `code-gen` directory for the source code of the code parser and generator.


