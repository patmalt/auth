import Foundation

enum CBORValue {
    case unsigned(UInt64)
    case negative(Int64)
    case byteString(Data)
    case text(String)
    case array([CBORValue])
    case map([(CBORValue, CBORValue)])
    case boolean(Bool)
    case null
}

extension CBORValue: Hashable {
    static func == (lhs: CBORValue, rhs: CBORValue) -> Bool {
        switch (lhs, rhs) {
        case (.unsigned(let a), .unsigned(let b)):
            return a == b
        case (.negative(let a), .negative(let b)):
            return a == b
        case (.byteString(let a), .byteString(let b)):
            return a == b
        case (.text(let a), .text(let b)):
            return a == b
        case (.array(let a), .array(let b)):
            return a == b
        case (.map(let a), .map(let b)):
            return a.elementsEqual(b, by: ==)
        case (.boolean(let a), .boolean(let b)):
            return a == b
        case (.null, .null):
            return true
        default:
            return false
        }
    }

    func hash(into hasher: inout Hasher) {
        switch self {
        case .unsigned(let value):
            hasher.combine(0)
            hasher.combine(value)
        case .negative(let value):
            hasher.combine(1)
            hasher.combine(value)
        case .byteString(let data):
            hasher.combine(2)
            hasher.combine(data)
        case .text(let string):
            hasher.combine(3)
            hasher.combine(string)
        case .array(let values):
            hasher.combine(4)
            hasher.combine(values)
        case .map(let entries):
            hasher.combine(5)
            for entry in entries {
                hasher.combine(entry.0)
                hasher.combine(entry.1)
            }
        case .boolean(let value):
            hasher.combine(6)
            hasher.combine(value)
        case .null:
            hasher.combine(7)
        }
    }
}

struct CBORReader {
    private let data: Data
    private(set) var index: Int = 0

    init(data: Data) {
        self.data = data
    }

    mutating func readValue() throws -> CBORValue {
        let initialByte = try readByte()
        let majorType = initialByte >> 5
        let additionalInfo = initialByte & 0x1f

        switch majorType {
        case 0:
            return .unsigned(try readLength(additionalInfo))
        case 1:
            let unsigned = try readLength(additionalInfo)
            return .negative(-1 - Int64(unsigned))
        case 2:
            let length = Int(try readLength(additionalInfo))
            return .byteString(try readData(length: length))
        case 3:
            let length = Int(try readLength(additionalInfo))
            let bytes = try readData(length: length)
            guard let string = String(data: bytes, encoding: .utf8) else {
                throw HTTPError.badRequest("Invalid CBOR UTF-8 string")
            }
            return .text(string)
        case 4:
            let count = Int(try readLength(additionalInfo))
            var values: [CBORValue] = []
            values.reserveCapacity(count)
            for _ in 0..<count {
                values.append(try readValue())
            }
            return .array(values)
        case 5:
            let count = Int(try readLength(additionalInfo))
            var entries: [(CBORValue, CBORValue)] = []
            entries.reserveCapacity(count)
            for _ in 0..<count {
                entries.append((try readValue(), try readValue()))
            }
            return .map(entries)
        case 7:
            switch additionalInfo {
            case 20:
                return .boolean(false)
            case 21:
                return .boolean(true)
            case 22:
                return .null
            default:
                throw HTTPError.badRequest("Unsupported CBOR simple value")
            }
        default:
            throw HTTPError.badRequest("Unsupported CBOR major type")
        }
    }

    private mutating func readByte() throws -> UInt8 {
        guard index < data.count else {
            throw HTTPError.badRequest("Unexpected end of CBOR data")
        }
        let byte = data[index]
        index += 1
        return byte
    }

    private mutating func readData(length: Int) throws -> Data {
        guard index + length <= data.count else {
            throw HTTPError.badRequest("Unexpected end of CBOR payload")
        }
        let slice = data[index..<(index + length)]
        index += length
        return Data(slice)
    }

    private mutating func readLength(_ info: UInt8) throws -> UInt64 {
        switch info {
        case 0...23:
            return UInt64(info)
        case 24:
            return UInt64(try readByte())
        case 25:
            let bytes = try readData(length: 2)
            return try UInt64(bytes.uint16BE(at: 0))
        case 26:
            let bytes = try readData(length: 4)
            return try UInt64(bytes.uint32BE(at: 0))
        case 27:
            let bytes = try readData(length: 8)
            return bytes.enumerated().reduce(UInt64(0)) { partial, item in
                partial | (UInt64(item.element) << UInt64((7 - item.offset) * 8))
            }
        default:
            throw HTTPError.badRequest("Unsupported CBOR additional info")
        }
    }
}

extension CBORValue {
    func mapValue() throws -> [CBORValue: CBORValue] {
        guard case .map(let entries) = self else {
            throw HTTPError.badRequest("Expected CBOR map")
        }
        return Dictionary(uniqueKeysWithValues: entries)
    }

    func byteStringValue() throws -> Data {
        guard case .byteString(let data) = self else {
            throw HTTPError.badRequest("Expected CBOR byte string")
        }
        return data
    }

    func textValue() throws -> String {
        guard case .text(let value) = self else {
            throw HTTPError.badRequest("Expected CBOR text")
        }
        return value
    }

    func intValue() throws -> Int64 {
        switch self {
        case .unsigned(let value):
            return Int64(value)
        case .negative(let value):
            return value
        default:
            throw HTTPError.badRequest("Expected CBOR integer")
        }
    }
}
