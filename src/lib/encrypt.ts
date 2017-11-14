/*
  Copyright (c) 2014 clowwindy

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
 */

/**
 * @author texasbruce
 */

import crypto = require("crypto");
import util = require("util");
import merge_sort = require("./merge_sort");

const INT32MAX = Math.pow(2, 32);
const METHOD_SUPPORTED = {
  "aes-128-cfb": [16, 16],
  "aes-192-cfb": [24, 16],
  "aes-256-cfb": [32, 16],
  "bf-cfb": [16, 8],
  "camellia-128-cfb": [16, 16],
  "camellia-192-cfb": [24, 16],
  "camellia-256-cfb": [32, 16],
  "cast5-cfb": [16, 8],
  "des-cfb": [8, 8],
  "idea-cfb": [16, 8],
  "rc2-cfb": [16, 8],
  "rc4": [16, 0],
  "rc4-md5": [16, 16],
  "seed-cfb": [16, 16],
};


export class Encryptor {

  private static bytes_to_key_results: any = {};
  private static cachedTables = {};

  private key: any;
  private method: any;
  private iv_sent: any;
  private cipher: any;
  private cipher_iv: any;
  private encryptTable: any;
  private decipher: any;
  private decryptTable: any;

  private static create_rc4_md5_cipher(key, iv, op) {
    let md5, rc4_key;
    md5 = crypto.createHash("md5");
    md5.update(key);
    md5.update(iv);
    rc4_key = md5.digest();
    if (op === 1) {
      return crypto.createCipheriv("rc4", rc4_key, "");
    } else {
      return crypto.createDecipheriv("rc4", rc4_key, "");
    }
  }


  public static getTable(key) {
    let ah, al, decrypt_table, hash, i, md5sum, result, table;
    if (this.cachedTables[key]) {
      return this.cachedTables[key];
    }
    util.log("calculating ciphers");
    table = new Array(256);
    decrypt_table = new Array(256);
    md5sum = crypto.createHash("md5");
    md5sum.update(key);
    hash = new Buffer(md5sum.digest(), "binary");
    al = hash.readUInt32LE(0);
    ah = hash.readUInt32LE(4);
    i = 0;
    while (i < 256) {
      table[i] = i;
      i++;
    }
    i = 1;
    while (i < 1024) {
      table = merge_sort.mergeSort(table, (x, y) => {
        return ((ah % (x + i)) * INT32MAX + al) % (x + i) - ((ah % (y + i)) * INT32MAX + al) % (y + i);
      });
      i++;
    }
    i = 0;
    while (i < 256) {
      decrypt_table[table[i]] = i;
      ++i;
    }
    result = [table, decrypt_table];
    this.cachedTables[key] = result;
    return result;
  }


  private static substitute(table, buf) {
    let i = 0;
    while (i < buf.length) {
      buf[i] = table[buf[i]];
      i++;
    }
    return buf;
  }

  private static EVP_BytesToKey(password, key_len, iv_len) {
    let count, d, data, i, iv, key, m, md5, ms;
    if (this.bytes_to_key_results["" + password + ":" + key_len + ":" + iv_len]) {
      return this.bytes_to_key_results["" + password + ":" + key_len + ":" + iv_len];
    }
    m = [];
    i = 0;
    count = 0;
    while (count < key_len + iv_len) {
      md5 = crypto.createHash("md5");
      data = password;
      if (i > 0) {
        data = Buffer.concat([m[i - 1], password]);
      }
      md5.update(data);
      d = md5.digest();
      m.push(d);
      count += d.length;
      i += 1;
    }
    ms = Buffer.concat(m);
    key = ms.slice(0, key_len);
    iv = ms.slice(key_len, key_len + iv_len);
    this.bytes_to_key_results[password] = [key, iv];
    return [key, iv];
  }
  public static encryptAll(password, method, op, data) {
    let cipher, decryptTable, encryptTable, iv, ivLen, iv_, key, keyLen, result, _ref, _ref1, _ref2;
    if (method === "table") {
      method = null;
    }
    if (method == null) {
      _ref = this.getTable(password), encryptTable = _ref[0], decryptTable = _ref[1];
      if (op === 0) {
        return this.substitute(decryptTable, data);
      } else {
        return this.substitute(encryptTable, data);
      }
    } else {
      result = [];
      method = method.toLowerCase();
      _ref1 = METHOD_SUPPORTED[method], keyLen = _ref1[0], ivLen = _ref1[1];
      password = new Buffer(password, "binary");
      _ref2 = this.EVP_BytesToKey(password, keyLen, ivLen), key = _ref2[0], iv_ = _ref2[1];
      if (op === 1) {
        iv = crypto.randomBytes(ivLen);
        result.push(iv);
      } else {
        iv = data.slice(0, ivLen);
        data = data.slice(ivLen);
      }
      if (method === "rc4-md5") {
        cipher = this.create_rc4_md5_cipher(key, iv, op);
      } else {
        if (op === 1) {
          cipher = crypto.createCipheriv(method, key, iv);
        } else {
          cipher = crypto.createDecipheriv(method, key, iv);
        }
      }
      result.push(cipher.update(data));
      result.push(cipher.final());
      return Buffer.concat(result);
    }
  }

  constructor(key, method) {
    let _ref;
    this.key = key;
    this.method = method;
    this.iv_sent = false;
    if (this.method === "table") {
      this.method = null;
    }
    if (this.method != null) {
      this.cipher = this.get_cipher(this.key, this.method, 1, crypto.randomBytes(32));
    } else {
      _ref = this.getClass().getTable(this.key), this.encryptTable = _ref[0], this.decryptTable = _ref[1];
    }
  }

  public getClass(): typeof Encryptor {
    return Encryptor;
  }

  private get_cipher(password, method, op, iv) {
    let iv_, key, m, _ref;
    method = method.toLowerCase();
    password = new Buffer(password, "binary");
    m = this.get_cipher_len(method);
    if (m != null) {
      _ref = this.getClass().EVP_BytesToKey(password, m[0], m[1]), key = _ref[0], iv_ = _ref[1];
      if (iv == null) {
        iv = iv_;
      }
      if (op === 1) {
        this.cipher_iv = iv.slice(0, m[1]);
      }
      iv = iv.slice(0, m[1]);
      if (method === "rc4-md5") {
        return this.getClass().create_rc4_md5_cipher(key, iv, op);
      } else {
        if (op === 1) {
          return crypto.createCipheriv(method, key, iv);
        } else {
          return crypto.createDecipheriv(method, key, iv);
        }
      }
    }
  }

  private get_cipher_len(method) {
    let m;
    method = method.toLowerCase();
    m = METHOD_SUPPORTED[method];
    return m;
  }

  private encrypt(buf) {
    let result;
    if (this.method != null) {
      result = this.cipher.update(buf);
      if (this.iv_sent) {
        return result;
      } else {
        this.iv_sent = true;
        return Buffer.concat([this.cipher_iv, result]);
      }
    } else {
      return this.getClass().substitute(this.encryptTable, buf);
    }
  }

  private decrypt(buf) {
    let decipher_iv, decipher_iv_len, result;
    if (this.method != null) {
      if (this.decipher == null) {
        decipher_iv_len = this.get_cipher_len(this.method)[1];
        decipher_iv = buf.slice(0, decipher_iv_len);
        this.decipher = this.get_cipher(this.key, this.method, 0, decipher_iv);
        result = this.decipher.update(buf.slice(decipher_iv_len));
        return result;
      } else {
        result = this.decipher.update(buf);
        return result;
      }
    } else {
      return this.getClass().substitute(this.decryptTable, buf);
    }
  }

}

export const encryptAll = Encryptor.encryptAll;
export const getTable = Encryptor.getTable;

export default Encryptor;
