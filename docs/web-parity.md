# Shield Web against the apps

Every screen and flow of the iOS and Android apps at v0.9.0, read from their source, and what the web
version does with it. Where the web differs, the difference is one a browser forces, and the screen
says so. [web.md](web.md) has the reasons.

## Making and opening a wallet

| The apps | The web |
|---|---|
| Welcome: create, or restore from a phrase | The same, after a one-time notice of what the web version trusts |
| Recovery phrase, 24 words, written down | The same. A browser cannot see a screenshot or a recording, so there is no warning on either |
| Restore by words, with the count of accounts looked at | The same |
| Restore by private key | The same |
| Locked, unlocked by Face ID, Touch ID or the screen lock | The same, unlocked by a passkey with PRF; a browser without one gets a refusal |
| The key is gone: destroy and restore | The same, from "The passkey is gone" |
| Jailbreak signs (iOS) | Not available in a browser |

## Home and the public account

| The apps | The web |
|---|---|
| Account pill, network menu, ETH, NOX and USDC | The same |
| Send, Receive, Swap, Shield | The same |
| Public send: review, contract warning, confirm, status, copy hash and link | The same, confirmed with the passkey |
| Receive at the 0x address, with a QR code | The same |
| Swap on mainnet: approval, review, slippage, route | The same, mainnet only, as in the apps' sideload builds |

## The shield

| The apps | The web |
|---|---|
| Shielded NOX and ETH, the privacy meter, read the pool, take back, details | The same |
| Deposit, with the approval first for NOX | The same |
| Deposit from another wallet, with Copy to and Copy data | The same |
| Private send and withdrawal: the notes on the address, the fee, the EARLY prompt | The same |
| Proving on the phone, with Cancel | The same in the browser, where the device can hold a proof; a phone first times one test proof, and one that cannot finish sends private sends to the app or a computer |
| Hand the spend to a lander over Tor, five steps to Settled | Settled from the user's public account, three steps, with what that reveals said first. A browser cannot reach an onion service |
| Settle it yourself | The way every spend settles on the web |
| Share the files | A download of the same files |
| Receive at the nox1 address, with a QR code | The same |

## Settings and the rest

| The apps | The web |
|---|---|
| Recovery words and keys | The same, after the passkey |
| Lock now, lock when idle, lock on leaving the app | The same; leaving is the page being hidden, and a running proof is left to finish |
| Screen recording hidden or allowed | Not available in a browser |
| Accounts, adding one, view-only accounts | The same |
| Measure: time a proof, export it, share the card | The same; the card has the lines a browser can fill in |
| Licences, from what the build linked | The same, from the web build's own crates and fonts |
| About and the Etna credit | The same |
| Destroy this wallet | The same |
| The pool read every five minutes in the background | Every five minutes while the page is open; a closed page reads nothing |
| Not in the apps | Add to the home screen, check this release, the update prompt, offline opening |
| Not in the apps | A line on Home and the shield while a deposit's note is unspent, with "Make it recoverable", a private send to the wallet's own address |

Neither app has a history of transactions, transaction details or endpoint settings, and neither
does the web version. Endpoints the user chooses come in a later release.
