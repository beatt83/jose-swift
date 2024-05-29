/*
 * Copyright 2024 Gonçalo Frade
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation

extension ClaimElement: Encodable {
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: DynamicCodingKey.self)
        switch element {
        case .codable(let obj):
            try container.encode(obj, forKey: .init(stringValue: key)!)
        case .element(let element):
            try container.encode(element, forKey: .init(stringValue: key)!)
        case .array(let elements):
            var nested = container.nestedUnkeyedContainer(forKey: .init(stringValue: key)!)
            try encodeArrayElements(container: &nested, elements: elements)
        case .object(let elements):
            var nested: KeyedEncodingContainer<DynamicCodingKey>
            if key.isEmpty {
                nested = container
            } else {
                nested = container.nestedContainer(keyedBy: DynamicCodingKey.self, forKey: .init(stringValue: key)!)
            }
            
            try encodeObjectElement(container: &nested, elements: elements)
        }
    }
    
    private func encodeArrayElements(container: inout UnkeyedEncodingContainer, elements: [ClaimElement]) throws {
        try elements.forEach {
            switch $0.element {
            case .codable(let obj):
                try container.encode(obj)
            case .element(let element):
                try container.encode(element)
            case .array(let elements):
                var nested = container.nestedUnkeyedContainer()
                try encodeArrayElements(container: &nested, elements: elements)
            case .object(let elements):
                var nested = container.nestedContainer(keyedBy: DynamicCodingKey.self)
                try encodeObjectElement(container: &nested, elements: elements)
            }
        }
    }
    
    private func encodeObjectElement(container: inout KeyedEncodingContainer<DynamicCodingKey>, elements: [ClaimElement]) throws {
        try elements.forEach {
            switch $0.element {
            case .codable(let obj):
                try container.encode(obj, forKey: .init(stringValue: $0.key)!)
            case .element(let element):
                try container.encode(element, forKey: .init(stringValue: $0.key)!)
            case .array(let elements):
                var nested = container.nestedUnkeyedContainer(forKey: .init(stringValue: $0.key)!)
                try encodeArrayElements(container: &nested, elements: elements)
            case .object(let elements):
                var nested = container.nestedContainer(keyedBy: DynamicCodingKey.self, forKey: .init(stringValue: $0.key)!)
                try encodeObjectElement(container: &nested, elements: elements)
            }
        }
    }
}

struct DynamicCodingKey: CodingKey {
    var stringValue: String
    init?(stringValue: String) {
        self.stringValue = stringValue
    }
    
    var intValue: Int?
    init?(intValue: Int) {
        self.stringValue = "\(intValue)"
        self.intValue = intValue
    }
}
