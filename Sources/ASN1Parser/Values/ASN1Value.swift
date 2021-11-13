//
//  ASN1Value.swift
//  
//
//  Created by Dominik Horn on 10.11.21.
//

import Foundation

public protocol ASN1Value {
  func isEqualTo(_ other: ASN1Value) -> Bool
}

public extension ASN1Value where Self: Equatable {
  func isEqualTo(_ other: ASN1Value) -> Bool {
    guard let other = other as? Self else { return false }
    return self == other
  }
}
