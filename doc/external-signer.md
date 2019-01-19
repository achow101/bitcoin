# Support for signing transactions outside of Bitcoin Core

Bitcoin Core can be launched with `-signer=<cmd>` where `<cmd>` is an external tool which can sign transactions and perform other functions. For example, it can be used to communicate with a hardware wallet.

## Example usage

The following example is based on the [HWI](https://github.com/achow101/HWI) tool. This tool is not officially supported or endorsed by the Bitcoin Core developers, and should be used with caution. When using a hardware wallet, consult the manufacturer website for (alternative) tools they recommend.

Start Bitcoin Core:

```sh
$ bitcoind -signer=../HWI/hwi.py
```
### Device setup

Follow the hardware manufacturers instructions for the initial device setup, as well as their instructions for creating a backup.

A future pull request could use the `setup_device`, `restore_device` and `backup_device` commands provided by [HWI](https://github.com/achow101/HWI), for wallets that support this.

### Create wallet and import keys

Create a watch-only wallet:

```sh
$ bitcoin-cli createwallet true

# A future PR could allow wallet specific signers:
# bitcoin-cli addsigner "../HWI/hwi.py"
```

Get a list of signing devices / services:

```
$ bitcoin-cli enumeratesigners
{
  "signers": [
    {
      "fingerprint": "c8df832a"
    }
]
```

The master key fingerprint is used to identify a device.

Import the public keys from the hardware device into the new wallet:

```
$ bitcoin-cli -rpcwallet=<wallet> signerfetchkeys 00000000
```

Replace `<wallet>` with the name of your new wallet. The fingerprint argument is optional; by default it will use the first available signer.

### Verify an address

Display an address on the device:

```sh
$ bitcoin-cli -rpcwallet=<wallet> getnewaddress
$ bitcoin-cli -rpcwallet=<wallet> signerdisplayaddress  <address>
```

Replace `<address>` with the result of `getnewaddress`.

### Spending the hard way

In order to send coins you need to create and sign a [Partially Signed Bitcoin Transaction](psbt.md), or use the convenience method `signersend` explained in the next section.

```sh
$ bitcoin-cli -rpcwallet=<wallet> walletcreatefundedpsbt '[]' '[{"<address>": <amount>}]' 0 '{"includeWatching": true}' true
<unsigned_psbt>
$ bitcoin-cli -rpcwallet=<wallet> walletprocesspsbt <unsigned_psbt>
<signed_psbt>
```

This prompt your hardware wallet to sign, and fail if it's not connected. It then returns the signed PSBT.

```sh
$ bitcoin-cli finalizepsbt <signed_psbt>
{"complete": true, "hex": <tx>}
$ bitcoin-cli sendrawtransaction <tx>
```

### Spending the easy way

Plug in your device.

```sh
$ bitcoin-cli -rpcwallet=<wallet> signerspend '[]' '[{"<address>": <amount>}]'
```

Confirm the transaction on your device.

If successful, the transaction is broadcast. If not, e.g. if it requires additional signatures, a PSBT is returned.

## Signer API

In order to be compatible with Bitcoin Core any signer command should conform to the specification below. This specification is subject to change. Ideally a BIP should propose a standard so that other wallets can also make use of it.

Prerequisite knowledge:
* [Output Descriptors](descriptors.md)
* Partially Signed Bitcoin Transaction ([PSBT](psbt.md))

### `enumerate` (required)

Usage:
```
$ <cmd> enumerate
[
    {
        "fingerprint": "00000000"
    }
]
```

The command MUST return an (empty) array with at least a `fingerprint` field.

TODO:
* optional return field with recommended change and receive pseudo-descriptors, and/or constraints on those descriptors (e.g. no native segwit support)
* optional return field `reachable`, in case `<cmd>` knows a signer exists but can't currently reach it

### `signtransaction` (required)

Usage:
```
$ <cmd> --fingerprint=<fingerprint> (--testnet) signtransaction --psbt=<psbt>
base64_encode_signed_psbt
```

The command returns a psbt with any signatures.

The `psbt` SHOULD include bip32 derivations. The command SHOULD fail if none of the bip32 derivations match a key owned by the device.

The command SHOULD fail if the user cancels (return code?).

The command MAY complain if `--testnet` is set, but any of the BIP32 derivation paths contain a coin type other than `1h` (and vice versa).

### `getkeys` (optional)

Usage:

```
$ <cmd> --fingerprint=<fingerprint> (--testnet) getkeys --desc <pseudo_descriptor>
["descriptor"]
```

Returns a descriptor.

Example, obtain SegWit receive addresses on Testnet:

```
$ <cmd> --fingerprint=00000000 --testnet getkeys --desc "wpkh(00000000/84h/1h/0h/0/*)"
["wpkh([00000000/84h/1h/0h]tpubDDUZ..../0/0)"]
```

A pseudo-descriptor is used without a (public) key, since that information is not known.

The master key fingerprint should have been obtained previously using `enumerate`.

If the pseudo-descriptor ends with `*h` then it must return an array of `<n>` descriptors. Otherwise `<n>` should not be used.

The command MUST be able to figure out the address type from the pseudo-descriptor.

The command MUST provide the public of the last hardened derivation.

The command MAY complain if `--testnet` is set, but the BIP32 coin type is not `1h` (and vice versa).

### `displayaddress` (optional)

Usage:
```
<cmd> --fingerprint=<fingerprint> (--testnet) displayaddress --desc descriptor
```

Example, display the first native SegWit receive address on Testnet:

```
<cmd> --fingerprint=00000000 --testnet displayaddress --desc "wpkh([00000000/84h/1h/0h]tpubDDUZ..../0/0)"
```

The command MUST be able to figure out the address type from the descriptor.

If <descriptor> contains a master key fingerprint, the command MUST fail if it does not match the fingerprint known by the device.

If <descriptor> contains an xpub, the command MUST fail if it does not match the xpub known by the device.

The command MAY complain if `--testnet` is set, but the BIP32 coin type is not `1h` (and vice versa).

## How Bitcoin Core uses the Signer API

The `enumeratesigners` RPC simply calls `<cmd> enumerate`.

The `signerfetchkeys (00000000)` RPC makes two calls:

* `<cmd> --fingerprint=00000000 getkeys --desc "wpkh(00000000/84h/1h/0h/0/*)"`
* `<cmd> --fingerprint=00000000 getkeys --desc "wpkh(00000000/84h/1h/0h/1/*)"`

These keys are for the receive and change keypools respectively. The `wpkh()` and `84h` parts of the pseudo-descriptor depends on `-addresstype` and `-changetype`.

We could add optional `receive_descriptor` and `change_descriptor` arguments to the `getkeys` RPC for signers that don't follow BIP 44/49/84.

The descriptors are then expanded and added to the keypool, internally calling code from `importmulti`. The number of keys depends on the keypool size setting.

The `displayaddress` RPC reuses some code from `getaddressinfo` on the provided address and obtains the inferred descriptor. It then calls `<cmd> --fingerprint=00000000 displayaddress --desc=<descriptor>`.

`signerprocesspsbt` checks `inputs->bip32_derivs` to see if any inputs have the same `master_fingerprint` as the (global / wallet) signer. If so, it calls `<cmd> --fingerprint=00000000 signtransaction --psbt=<psbt>` and waits for the device to return a (partially) signed psbt.
