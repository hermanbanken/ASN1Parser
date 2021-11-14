import XCTest
@testable import ASN1Parser

final class FullParseTests: XCTestCase {
  func testParsingECPublicKeyDER() throws {
    guard let derData = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQPtmXeh4gkzq30Zq3LXdgcl39fgCOBRZExhNWgZTSv5NTvbRoZNx28Ln/+Wtkfc42nWdunurluAeMPr0BrnLtA==")
    else {
      XCTFail()
      return
    }
    
    let tree = try DERParser.parse(der: derData)
    print(try tree.asSequence[1].asBitString)
  }
  
  func testRandomDER() throws {
    let derData = Data([
      DERParser.Tag.sequence.rawValue, 0x13,
        DERParser.Tag.sequence.rawValue, 0x05,
          DERParser.Tag.null.rawValue, 0x00,
          DERParser.Tag.integer.rawValue, 0x01, 0x85,
        DERParser.Tag.boolean.rawValue, 0x01, 0x01,
        DERParser.Tag.objectIdentifier.rawValue, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    ])
    
    let tree = try DERParser.parse(der: derData)
    print(tree)
    
    XCTAssertEqual(try tree.asSequence.count, 3)
    XCTAssertEqual(try tree.asSequence[0].asSequence.count, 2)
    XCTAssertEqual(try tree.asSequence[0].asSequence[0].asNull, ASN1Null())
    XCTAssertEqual(try tree.asSequence[0].asSequence[1].asInt, ASN1Integer(-5))
    XCTAssertEqual(try tree.asSequence[1].asBool, ASN1Boolean(true))
    print(try tree.asSequence[2].asObjectIdentifier)
    XCTAssertEqual(try tree.asSequence[2].asObjectIdentifier, try ASN1ObjectIdentifier(oid: "1.2.840.10045.2.1"))
    
    XCTAssertThrowsError(try tree.asInt)
    XCTAssertThrowsError(try tree.asSequence[3])
    XCTAssertThrowsError(try tree.asSequence[0].asSequence[1337])
    XCTAssertThrowsError(try tree.asSequence[0].asBool)
  }
}
