##ONYX2

Opalcoin V2 is a relaunch of the original Opalcoin. We made some minor modifications to the codebase including a removed pre-mine and decreased Proof-of-Work period. 

* Opalcoin V2 - X13 CryptoCurrency
* RPC Port: 51990
* P2P Port: 50990
* Algorithm: X13 POW/POS starts on block 15,000
* Ticker: ONYX2
* Max PoW Coins: Approximately 15 million
* 5% PoS Annual Interest

* Block Reward Schedule:
* 90 second blocks
* No Pre-Mine
* Block 0-50 are low reward (15)
* Block 50-15,000 are 1,000
* PoW Ends on Block 15,000 (approx. 15 days)

* MinStakeAge: 24 hours 
* Max: Unlimited

##Troubleshooting

In the event you encounter problems compiling the daemon, feel free to consult the guide below:

Receive the following error?

------------------------------------------

PROBLEM:

g++: error: /home/user/Desktop/opal/OpalCoin/src/leveldb/libleveldb.a: No such file or directory
g++: error: /home/user/Desktop/opal/OpalCoin/src/leveldb/libmemenv.a: No such file or directory

SOLUTION:

cd src/leveldb
make libleveldb.a libmemenv.a

CD back to src and try to build it again.

If you get the following error trying to do the above,

/bin/sh: 1: ./build_detect_platform: Permission denied
Makefile:18: build_config.mk: No such file or directory

chmod 755 src/leveldb/build_detect_platform

and try it again.

http://www.theopalcoin.com

https://bitcointalk.org/index.php?topic=724186.0

------------------------------------------


