/*
  Copyright (c) 2014 clowwindy

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and permission notice shall be included in
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

import crypto from "crypto";
import util from "util";

import {mergeSort} from "./merge_sort";
import {Hash} from "./Hash";

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


type TablePair = [Array<number>, Array<number>];
type BufferPair = [Buffer, Buffer];
type Cipher = crypto.Cipher | crypto.Decipher;

interface Encryptor {
  key: Buffer;
  method: string;
  iv_sent: boolean;
  cipher_iv: Buffer;
  cipher: Cipher;
  decipher: Cipher;
  encryptTable: Array<number>;
  decryptTable: Array<number>;
}


const bytes_to_key_results: Hash<BufferPair> = {};
const cachedTables: {[key: string]: TablePair} = {};

function create_rc4_md5_cipher(key: Buffer, iv: Buffer, op: number): Cipher {
  let md5 = crypto.createHash("md5").update(key).update(iv);
  let rc4_key = md5.digest();
  if (op === 1) {
    return crypto.createCipheriv("rc4", rc4_key, "");
  } else {
    return crypto.createDecipheriv("rc4", rc4_key, "");
  }
}

function getTable(key: Buffer): TablePair {

  if (cachedTables[key.toString()]) {
    return cachedTables[key.toString()];
  }

  util.log("calculating ciphers");

  let table: Array<number> = new Array<number>(256);
  let decrypt_table: Array<number> = new Array<number>(256);
  let md5sum: crypto.Hash = crypto.createHash("md5").update(key);
  let hash: Buffer = new Buffer(md5sum.digest().toString(), "binary");
  let al: number = hash.readUInt32LE(0);
  let ah: number = hash.readUInt32LE(4);

  let i: number;
  for (i = 0; i < 256; i++) {
    table[i] = i;
  }
  // TODO What is going on here? Reassign table 1024 times?
  for (i = 1; i < 1024; i++) {
    table = mergeSort(table, (x, y) => {
      return ((ah % (x + i)) * INT32MAX + al) % (x + i) - ((ah % (y + i)) * INT32MAX + al) % (y + i);
    });
  }
  for (i = 0; i < 256; i++) {
    decrypt_table[table[i]] = i;
  }

  return cachedTables[key.toString()] = [table, decrypt_table];
}


function substitute(table: Array<number>, buf: Buffer): Buffer{
  for (let i = 0; i < buf.length; i++) {
    buf[i] = table[buf[i]];
  }
  return buf;
}

function EVP_BytesToKey(password: Buffer, key_len: number, iv_len: number): BufferPair {
  if (bytes_to_key_results["" + password + ":" + key_len + ":" + iv_len]) {
    return bytes_to_key_results["" + password + ":" + key_len + ":" + iv_len];
  }

  let d: Buffer, data: Buffer, iv: Buffer, key: Buffer, md5: crypto.Hash, ms: Buffer;
  let m: Buffer[] = [];
  let i: number = 0;
  let count: number = 0;
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
  bytes_to_key_results[password.toString()] = [key, iv];
  return [key, iv];
}
function encryptAll(password: Buffer, method: string, op: number, data: Buffer): Buffer {
  let cipher: Cipher, decryptTable: Array<number>, encryptTable: Array<number>, iv: Buffer, ivLen: number, 
    iv_, key: Buffer, keyLen: number;
  if (method === "table") {
    method = null;
  }
  if (method == null) {
    [encryptTable, decryptTable] = getTable(password);
    if (op === 0) {
      return substitute(decryptTable, data);
    } else {
      return substitute(encryptTable, data);
    }
  } else {
    let result: Array<Buffer> = [];
    method = method.toLowerCase();
    [keyLen, ivLen] = METHOD_SUPPORTED[method];
    password = new Buffer(password.toString(), "binary");
    [key, iv_] = EVP_BytesToKey(password, keyLen, ivLen);
    if (op === 1) {
      iv = crypto.randomBytes(ivLen);
      result.push(iv);
    } else {
      iv = data.slice(0, ivLen);
      data = data.slice(ivLen);
    }
    if (method === "rc4-md5") {
      cipher = create_rc4_md5_cipher(key, iv, op);
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

// TODO change property or local?
function Encryptor(key: Buffer, method) : Encryptor {

  let res: Encryptor = {} as any;

  res.key = key;
  res.method = method === "table" ? null : method;
  res.iv_sent = false;

  if (method != null) {
    res.cipher = get_cipher(res, key, method, 1, crypto.randomBytes(32));
  } else {
    [res.encryptTable, res.decryptTable] = getTable(key);
  }

  return res;
}

function get_cipher(enc: Encryptor, password: Buffer, method: string, op: number, iv: Buffer) {
  let iv_: Buffer, key: Buffer, m: Array<number>;
  method = method.toLowerCase();
  password = new Buffer(password.toString(), "binary");
  m = get_cipher_len(method);
  if (m != null) {
    [key, iv_] = EVP_BytesToKey(password, m[0], m[1]);
    if (iv == null) {
      iv = iv_;
    }
    if (op === 1) {
      enc.cipher_iv = iv.slice(0, m[1]);
    }
    iv = iv.slice(0, m[1]);
    if (method === "rc4-md5") {
      return create_rc4_md5_cipher(key, iv, op);
    } else {
      if (op === 1) {
        return crypto.createCipheriv(method, key, iv);
      } else {
        return crypto.createDecipheriv(method, key, iv);
      }
    }
  }
}

function get_cipher_len(method: string): Array<number> {
  return METHOD_SUPPORTED[method.toLowerCase()];
}

function encrypt(enc: Encryptor, buf: Buffer): Buffer {
  let result: Buffer;
  if (enc.method != null) {
    result = enc.cipher.update(buf);
    if (enc.iv_sent) {
      return result;
    } else {
      enc.iv_sent = true;
      return Buffer.concat([enc.cipher_iv, result]);
    }
  } else {
    return substitute(enc.encryptTable, buf);
  }
}

function decrypt(enc: Encryptor, buf: Buffer): Buffer {
  let decipher_iv: Buffer, decipher_iv_len: number, result: Buffer;
  if (enc.method != null) {
    if (enc.decipher == null) {
      decipher_iv_len = get_cipher_len(enc.method)[1];
      decipher_iv = buf.slice(0, decipher_iv_len);
      enc.decipher = get_cipher(enc, enc.key, enc.method, 0, decipher_iv);
      result = enc.decipher.update(buf.slice(decipher_iv_len));
      return result;
    } else {
      result = enc.decipher.update(buf);
      return result;
    }
  } else {
    return substitute(enc.decryptTable, buf);
  }
}


export {Encryptor, encryptAll, getTable};
