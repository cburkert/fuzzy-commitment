[![Build Status](https://travis-ci.org/cburkert/fuzzy-commitment.svg?branch=master)](https://travis-ci.org/cburkert/fuzzy-commitment)

FCS: Fuzzy Commitment Scheme
============================

This implementation follows the scheme presented by [Juels and Wattenberg in 1999](http://doi.acm.org/10.1145/319709.319714)
and includes the improvements of [Kelkboom et al. in 2011](https://ieeexplore.ieee.org/abstract/document/5634099/).

**Warning**: This has not been independently audited and should **not**
be used for productive or even critical applications.


## Installation

You can easily install it using pip:

    pip3 install -U git+https://github.com/cburkert/fuzzy-commitment.git


## Usage

Have a look at the help:

```python
>>> import fcs
>>> help(fcs.FCS)
```

A simple usage example:

```python
>>> cs = fcs.FCS[bytes](8, 1)
>>> c = cs.commit(b"\x01")  # uses a random message to commit to
>>> cs.verify(c, b"\x03")  # Verification succeeds. One bit changed.
True
>>> cs.verify(c, b"\x02")  # Verification fails. Two bits changed.
False
```
