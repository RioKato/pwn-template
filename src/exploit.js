
var code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);
var module = new WebAssembly.Module(code);
var instance = new WebAssembly.Instance(module);
var main = instance.exports.main;

class Helpers {
  constructor() {
    this.buf = new ArrayBuffer(8);
    this.f32 = new Float32Array(this.buf);
    this.f64 = new Float64Array(this.buf);
    this.u32 = new Uint32Array(this.buf);
    this.u64 = new BigUint64Array(this.buf);
  }

  ftoi(f) {
    this.f32[0] = f;
    return this.u32[0];
  }

  itof(i) {
    this.u32[0] = i;
    return this.f32[0];
  }

  f64toi64(f) {
    this.f64[0] = f;
    return this.u64[0];
  }

  i64tof64(i) {
    this.u64[0] = i;
    return this.f64[0];
  }

  major_gc() {
    new ArrayBuffer(0x80000000);
  }

  minor_gc() {
    var a = [];
    for (var i = 0; i < 100000; i++) {
      a[i] = new String("");
    }
  }

  debug(sym, val) {
    console.log(sym + '= 0x' + val.toString(16));
  }
}

var helpers = new Helpers();
