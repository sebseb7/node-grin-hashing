# node-grin-hashing

example:

const cu = require('grin-hashing');

cu.unscaled_diff(request.params.edge_bits, request.params.pow);

var ar_scale = bignum(grindaemon.current_pow.substr(grindaemon.current_pow.length - 8),16).toNumber();

cu.scaled_diff(request.params.edge_bits, request.params.pow, ar_scale);

var header =  Buffer.concat([Buffer.from(set_pre(grindaemon.current_pow,miner.difficulty), 'hex'),bignum(request.params.nonce,10).toBuffer({endian : 'big',size : 8})]);
var prooferror = cu.cuckoo(header,request.params.pow,request.params.edge_bits);
