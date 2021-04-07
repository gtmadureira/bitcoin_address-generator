var bech32 = require('./bech32');

module.exports = {
  encode: encode,
  decode: decode
};

function convertbits (data, frombits, tobits, pad) {
  var acc = 0;
  var bits = 0;
  var ret = [];
  var maxv = (1 << tobits) - 1;
  for (var p = 0; p < data.length; ++p) {
    var value = data[p];
    if (value < 0 || (value >> frombits) !== 0) {
      return null;
    }
    acc = (acc << frombits) | value;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      ret.push((acc << (tobits - bits)) & maxv);
    }
  } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
    return null;
  }
  return ret;
}

function decode (hrp, addr) {
  var bech32m = false;
  var dec = bech32.decode(addr, bech32.encodings.BECH32);
  if (dec === null) {
    dec = bech32.decode(addr, bech32.encodings.BECH32M);
    bech32m = true;
  }
  if (dec === null || dec.hrp !== hrp || dec.data.length < 1 || dec.data[0] > 16) {
    return null;
  }
  var res = convertbits(dec.data.slice(1), 5, 8, false);
  if (res === null || res.length < 2 || res.length > 40) {
    return null;
  }
  if (dec.data[0] === 0 && res.length !== 20 && res.length !== 32) {
    return null;
  }
  if (dec.data[0] === 0 && bech32m) {
    return null;
  }
  if (dec.data[0] !== 0 && !bech32m) {
    return null;
  }
  return {version: dec.data[0], program: res};
}

function encode (hrp, version, program) {
  var enc = bech32.encodings.BECH32;
  if (version > 0) {
    enc = bech32.encodings.BECH32M;
  }
  var ret = bech32.encode(hrp, [version].concat(convertbits(program, 8, 5, true)), enc);
  if (decode(hrp, ret, enc) === null) {
    return null;
  }
  return ret;
}
