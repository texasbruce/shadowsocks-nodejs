// Author: texasbruce

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

function merge <T>(left: Array<T>, right: Array<T>, comparator: (lhs:T , rhs: T) => number): Array<T> {
  let result = new Array<T>();
  while ((left.length > 0) && (right.length > 0)) {
    if (comparator(left[0], right[0]) <= 0) {
      result.push(left.shift());
    } else {
      result.push(right.shift());
    }
  }
  while (left.length > 0) {
    result.push(left.shift());
  }
  while (right.length > 0) {
    result.push(right.shift());
  }
  return result;
};

function mergeSort <T>(array: Array<T>, comparator: (lhs:T , rhs: T) => number): Array<T> {
  let middle: number;
  if (array.length < 2) {
    return array;
  }
  middle = Math.ceil(array.length / 2);
  return merge(mergeSort(array.slice(0, middle), comparator), 
    mergeSort(array.slice(middle), comparator), comparator);
};

export {mergeSort};
