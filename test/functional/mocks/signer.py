#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys
import argparse
import json

def enumerate(args):
  sys.stdout.write(json.dumps([{"fingerprint": "00000001"}, {"fingerprint": "00000002"}, {"fingerprint": "d95fc47e"}]))

def getkeys(args):
  if args.desc == "wpkh(00000001/84h/1h/0h/0/*)":
    sys.stdout.write(json.dumps(["wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*)"]))
  elif args.desc == "wpkh(00000001/84h/1h/0h/1/*)":
    sys.stdout.write(json.dumps(["wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*)"]))
  elif args.desc == "sh(wpkh(00000001/49h/1h/0h/0/*))":
    sys.stdout.write(json.dumps(["sh(wpkh([00000001/49h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*))"]))
  elif args.desc == "sh(wpkh(00000001/49h/1h/0h/1/*))":
    sys.stdout.write(json.dumps(["sh(wpkh([00000001/49h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*))"]))
  elif args.desc == "pkh(00000001/44h/1h/0h/0/*)":
    sys.stdout.write(json.dumps(["pkh([00000001/44h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*)"]))
  elif args.desc == "pkh(00000001/44h/1h/0h/1/*)":
    sys.stdout.write(json.dumps(["pkh([00000001/44h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/*)"]))
  else:
    print("Pseudo-descriptor not recognized: " + args.desc)
    exit(1)

def displayaddress(args):
    return sys.stdout.write(json.dumps(None))

def signtx(args):
    if args.fingerprint == "d95fc47e" or args.fingerprint == "00000001" :
        # TODO: generate more realistic psbt and get rid of temporary extra fingerprint
        sys.stdout.write(json.dumps({
            "psbt": "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA"
        }))
    else:
        sys.stdout.write(json.dumps({"psbt": args.psbt}))

parser = argparse.ArgumentParser(prog='./signer.py', description='External signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--testnet', action='store_true')
subparsers = parser.add_subparsers()

parser_enumerate = subparsers.add_parser('enumerate', help='list available signers')
parser_enumerate.set_defaults(func=enumerate)

parser_getkeys = subparsers.add_parser('getkeys', help='get keys from signer')
parser_getkeys.add_argument('--desc', metavar='desc',
                    help='a pseudo-descriptor for the keys to fetch')
parser_getkeys.set_defaults(func=getkeys)

parser_displayaddress = subparsers.add_parser('displayaddress', help='display address on signer')
parser_displayaddress.add_argument('--desc', metavar='desc')
parser_displayaddress.set_defaults(func=displayaddress)

parser_signtx = subparsers.add_parser('signtx')
parser_signtx.add_argument('--psbt', metavar='psbt')

parser_signtx.set_defaults(func=signtx)

if len(sys.argv) == 1:
  args = parser.parse_args(['-h'])
  exit()

args = parser.parse_args()

args.func(args)
