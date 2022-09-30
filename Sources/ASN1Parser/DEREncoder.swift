//
//  File.swift
//  
//
//  Created by Herman Banken on 19/09/2022.
//

import Foundation

/// Parser for writing DER encoded ASN.1 data
public struct DEREncoder {
  /**
   Parse DER encoded ASN.1 data into an ASN.1 value tree

   - Parameter der: binary data, that will be decoded in this order, e.g., starting at index der.startIndex an moving to der.endIndex

   - Throws ``ASN1ParsingError`` when parsing fails, e.g., due to invalid encoding
   */
  public static func encode(der: ASN1Value) -> Data {
    switch der {
    case let value as ASN1Integer:
      return [Tag.integer.rawValue] + value.serialize()
    case let value as ASN1ObjectIdentifier:
      let oid = value.serialize()
      return [Tag.objectIdentifier.rawValue] + base128Encode(oid.count) + oid
    case let value as ASN1Sequence:
      let data = value.values.flatMap({ DEREncoder.encode(der: $0) })
      return Data([Tag.sequence.rawValue, UInt8(data.count)] + data)
    case let value as ASN1BitString:
      let data = value.serialize()
      return Data([Tag.bitString.rawValue, UInt8(data.count)] + data)
    case let value as ASN1OctetString:
      let data = value.bytes
      return Data([Tag.octetString.rawValue, UInt8(data.count)] + data)

    default:
      assertionFailure("Unknown cell dequeued \(type(of: self))")
      return Data()
    }
  }
}
