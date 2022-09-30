//
//  ASN1ObjectIdentifier+DER.swift
//  
//
//  Created by Dominik Horn on 14.11.21.
//

import Foundation
import BigInt

extension ASN1ObjectIdentifier: DERDecodable {
  /// https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
  init(der: Data) throws {
    let firstByte = try der.tryAccess(at: der.startIndex)

    // parse first byte
    nodes.append(BigUInt(firstByte / 40))
    nodes.append(BigUInt(firstByte % 40))
    
    // parse remaining bytes
    var baseOffset = der.startIndex + 1
    while baseOffset < der.endIndex {
      var lastByteOffset = baseOffset
      var lastByteSize = 1
      while try der.tryAccess(at: lastByteOffset).bit(at: 7) {
        lastByteOffset += 1
        lastByteSize += 1
      }
      
      var bytes = [UInt8](repeating: 0x00, count: lastByteSize)
      var lastAvailable = 0
      
      for (offset, i) in zip(baseOffset...lastByteOffset, 0..<lastByteSize).reversed() {
        let byte = try der.tryAccess(at: offset) & ((0x1 << 7) - 1)
        
        // store upper (7 - lastAvailable)
        bytes[i] = byte >> lastAvailable
        
        if lastAvailable > 0, i+1 < bytes.count {
          // extract lowest lastAvailable bits, shift into place and prepend
          let lowestK = byte & ((0x1 << lastAvailable) - 1)
          let lowestShifted = lowestK << (1 + 7 - lastAvailable)
          bytes[i+1] = lowestShifted | bytes[i+1]
        }
        lastAvailable = (lastAvailable + 1) % 8
      }
      
      nodes.append(BigUInt(Data(bytes)))
      baseOffset = lastByteOffset + 1
    }
    
    assert(baseOffset == der.endIndex)
  }
}

extension ASN1ObjectIdentifier: DEREncodable {
  // See https://gist.github.com/hfossli/00adac5c69116e7498e107d8d5ec61d4
  func serialize() -> Data {
    // First and second nodes are in 1 output byte
    let firstNode = nodes.first ?? BigUInt(0)
    let secondNode = nodes.dropFirst(1).first ?? BigUInt(0)
    let combined = UInt8(firstNode.multiplied(by: 40) + secondNode)
    let mapped: [Int] = nodes.dropFirst(2).compactMap({ node in
      guard let word = node.words.first else {return nil}
      return Int(word)
    })
    return Data([combined]) + mapped.flatMap(base128Encode)
  }
}

// See https://gist.github.com/hfossli/00adac5c69116e7498e107d8d5ec61d4
func base128Encode(_ int: Int) -> Data {
    var result = Data()
    var value = int
    repeat {
        let byte = UInt8(value & 0b0111_1111) | 0b1000_0000
        result.insert(byte, at: 0)
        value >>= 7
    } while value != 0
    result.append((result.popLast() ?? 0) & 0b0111_1111)
    return result
}
