var stls = require('../splittls');

var util = require('util');
var Duplex = require('stream').Duplex;
var Buffer = require('buffer').Buffer;

function Parser() {
  Duplex.call(this);
  this._readableState.objectMode = true;

  this.state = 'header';
  this.frame = null;
  this.waiting = 8;

  this.buffer = [];
  this.length = 0;
}
util.inherits(Parser, Duplex);
exports.Parser = Parser;

Parser.prototype._read = function _read() {
  // We only `push` stuff
};

Parser.prototype._write = function _write(data, enc, cb) {
  this.buffer.push(data);
  this.length += data.length;
  cb();

  while (this.length >= this.waiting) {
    var chunk = Buffer.concat(this.buffer, this.length);
    if (chunk.length >= this.waiting) {
      this.buffer = [ chunk.slice(this.waiting) ];
      this.length = this.buffer[0].length;
    } else {
      this.buffer = [];
      this.length = 0;
    }

    this.process(chunk);
  }
};

Parser.prototype.process = function process(chunk) {
  if (this.state === 'header') {
    this.state = 'body';
    this.frame = new Frame(chunk.readUInt16BE(0, true),
                           chunk.readUInt16BE(2, true),
                           chunk.readUInt32BE(4, true));
    this.waiting = this.frame.size;
  } else {
    var frame = this.frame;
    this.frame = null;

    this.state = 'header';
    this.waiting = 8;

    frame.body = chunk;
    this.push(frame);
  }
};

function Frame(version, type, size) {
  this.version = version;
  this.type = stls.constants.frameType[type];
  this.size = size;

  this.body = null;
}
