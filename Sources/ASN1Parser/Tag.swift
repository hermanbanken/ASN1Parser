//
//  File.swift
//  
//
//  Created by Herman Banken on 19/09/2022.
//

import Foundation

/// As documented in https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-tag-bytes
public enum Tag: UInt8 {
  case boolean = 0x01
  case integer = 0x02
  case bitString = 0x03
  case octetString = 0x04
  case null = 0x05
  case objectIdentifier = 0x06
  case utf8String = 0x0C
  case sequence = 0x30
  case set = 0x31

  init(_ der: Data, offset: inout Data.Index) throws {
    let firstByte = try der.tryAccess(at: offset)
    guard let tag = Tag(rawValue: firstByte) else {
      throw ASN1DERParsingError.unreadableTag(firstByte)
    }
    self = tag
    offset += 1
  }
}
