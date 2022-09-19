//
//  DERParser+TLV.swift
//  
//
//  Created by Dominik Horn on 10.11.21.
//

import Foundation
import BigInt

extension DERParser {
  /// As documented in https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-length-and-value-bytes
  struct Length {
    var value: Int
    
    init(_ der: Data, offset: inout Data.Index) throws {
      let firstByte = try der.tryAccess(at: offset)
      offset += 1
      
      value = Int(firstByte)
      
      if firstByte.bit(at: 7) {
        let trailingByteCount = Int(firstByte & ((0x1 << 7) - 1))
        
        guard trailingByteCount > 0 && trailingByteCount < MemoryLayout<Int>.size else {
          throw ASN1DERParsingError.unsupportedTLVLength
        }

        let dataView = der[offset..<(offset+trailingByteCount)]
        offset += trailingByteCount
        (dataView as NSData).getBytes(&value, length: MemoryLayout<Int>.size)
      }
    }
  }
  
  internal static func parseTLV(_ der: Data, offset: inout Data.Index) throws -> ASN1Value {
    let tag = try Tag(der, offset: &offset)
    let length = try Length(der, offset: &offset)
    
    // perform bounds check before access
    guard length.value <= der.endIndex - offset else {
      throw ASN1DERParsingError.invalidTLVLength
    }
    
    // each tag identifies a specific ASN1Value
    var value: ASN1Value
    let derView = length.value > 0 ? der[offset..<(offset+length.value)] : .init()
    
    switch tag {
    case .null:
      value = try ASN1Null(der: derView)
    case .boolean:
      value = try ASN1Boolean(der: derView)
    case .integer:
      value = try ASN1Integer(der: derView)
    case .objectIdentifier:
      value = try ASN1ObjectIdentifier(der: derView)
    case .bitString:
      value = try ASN1BitString(der: derView)
    case .octetString:
      value = try ASN1OctetString(der: derView)
    case .utf8String:
      value = try ASN1UTF8String(der: derView)
    case .sequence:
      value = try ASN1Sequence(der: derView)
    case .set:
      value = try ASN1Set(der: derView)
    }
    
    offset += length.value
    return value
  }
}
