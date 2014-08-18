var constants = exports;

function reverseNum(obj) {
  var res = {};

  Object.keys(obj).forEach(function(key) {
    var val = this[key];
    res[val] = key | 0;
  }, obj);

  return res;
}

constants.version = 1;

constants.frameType = {
  1: 'modExp',
  2: 'modExpReply'
};
constants.frameTypeByName = reverseNum(constants.frameType);
