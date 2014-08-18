var stls = require('../splittls');

var util = require('util');
var Buffer = require('buffer').Buffer;
var Readable = require('stream').Readable;

function Framer() {
  Readable.call(this);
}
util.inherits(Framer, Readable);
exports.Framer = Framer;

Framer.prototype._read = function _read() {
  // We only push
};

Framer.prototype.frame = function frame(type, body) {
  var hdr = new Buffer(8);

  hdr.writeUInt16BE(stls.constants.version, 0, true);
  hdr.writeUInt16BE(stls.constants.frameTypeByName[type], 2, true);
  hdr.writeUInt32BE(body.length, 4, true);

  this.push(hdr);
  this.push(body);
};
