
const bignum = require('bignum');
const cu = require('bindings')('grin-hashing.node');

function scaled_diff(bits,pow,ar_scale)
{
	return unscaled_diff(bits, pow, (bits == 31) ? 7936 : ar_scale);
}

function unscaled_diff(bits,pow,scale = 1)
{
	var hash = (bits==31)?cu.cyclehash31(pow):cu.cyclehash29(pow);

	var hashcopy = Buffer.from(hash);
	var hashNum = bignum.fromBuffer(hashcopy.reverse());
	return bignum(1).shiftLeft(256).sub(scale).div(hashNum).toNumber();
}
				
function cuckoo(header,pow,bits) {
	return (bits == 31)?cu.cuckatoo31(header,pow):cu.cuckaroo29(header,pow);
}

module.exports.cuckoo = cuckoo;
module.exports.scaled_diff = scaled_diff;
module.exports.unscaled_diff = unscaled_diff;

