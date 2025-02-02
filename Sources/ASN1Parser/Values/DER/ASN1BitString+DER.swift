//
//  ASN1BitString+DER.swift
//  
//
//  Created by Dominik Horn on 14.11.21.
//

import Foundation

extension ASN1BitString: DERDecodable {
  /// https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-bit-string
  init(der: Data) throws {
    let lastUnused = try Int(der.tryAccess(at: der.startIndex))
    guard lastUnused <= 8, der.startIndex + 1 < der.endIndex else {
      throw ASN1ValueParsingError.invalidBitString
    }
    
    let rawBytes = [UInt8](der[(der.startIndex+1)..<der.endIndex])
    
    // correctly shift in place on decode to avoid O(n) access cost
    self.bytes = (0..<rawBytes.count).map { (i: Int) in
        UInt8(rawBytes[i] >> lastUnused) | UInt8(i > 0 ? rawBytes[i-1] << (8 - lastUnused) : 0x00)
      }
    self.paddingLength = lastUnused
  }
}

extension ASN1BitString: DEREncodable {
  func serialize() -> Data {
    return Data([UInt8(paddingLength)] + (0..<bytes.count).map { (i: Int) in
      UInt8(bytes[i] << paddingLength) | UInt8(i > 0 ? bytes[i-1] >> (8 - paddingLength) : 0x00)
    })
  }
}
