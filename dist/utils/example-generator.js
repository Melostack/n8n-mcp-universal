"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExampleGenerator = void 0;
const crypto_1 = __importDefault(require("crypto"));
class ExampleGenerator {
    static generateFromNodeDefinition(nodeDefinition) {
        const nodeName = nodeDefinition.displayName || 'Example Node';
        const nodeType = nodeDefinition.name || 'n8n-nodes-base.exampleNode';
        return {
            name: `${nodeName} Example Workflow`,
            nodes: [
                {
                    parameters: this.generateExampleParameters(nodeDefinition),
                    id: this.generateNodeId(),
                    name: nodeName,
                    type: nodeType,
                    typeVersion: nodeDefinition.version || 1,
                    position: [250, 300],
                },
            ],
            connections: {},
            active: false,
            settings: {},
            tags: ['example', 'generated'],
        };
    }
    static generateExampleParameters(nodeDefinition) {
        const params = {};
        if (Array.isArray(nodeDefinition.properties)) {
            for (const prop of nodeDefinition.properties) {
                if (prop.name && prop.type) {
                    params[prop.name] = this.generateExampleValue(prop);
                }
            }
        }
        if (nodeDefinition.displayName?.toLowerCase().includes('trigger')) {
            params.pollTimes = {
                item: [
                    {
                        mode: 'everyMinute',
                    },
                ],
            };
        }
        return params;
    }
    static generateExampleValue(property) {
        switch (property.type) {
            case 'string':
                if (property.name.toLowerCase().includes('url')) {
                    return 'https://example.com';
                }
                if (property.name.toLowerCase().includes('email')) {
                    return 'user@example.com';
                }
                if (property.name.toLowerCase().includes('name')) {
                    return 'Example Name';
                }
                return property.default || 'example-value';
            case 'number':
                return property.default || 10;
            case 'boolean':
                return property.default !== undefined ? property.default : true;
            case 'options':
                if (property.options && property.options.length > 0) {
                    return property.options[0].value;
                }
                return property.default || '';
            case 'collection':
            case 'fixedCollection':
                return {};
            default:
                return property.default || null;
        }
    }
    static generateNodeId() {
        return crypto_1.default.randomBytes(16).toString('hex');
    }
    static generateFromOperations(operations) {
        const examples = [];
        if (!operations || operations.length === 0) {
            return examples;
        }
        const resourceMap = new Map();
        for (const op of operations) {
            if (!resourceMap.has(op.resource)) {
                resourceMap.set(op.resource, []);
            }
            resourceMap.get(op.resource).push(op);
        }
        for (const [resource, ops] of resourceMap) {
            examples.push({
                resource,
                operation: ops[0].operation,
                description: `Example: ${ops[0].description}`,
                parameters: {
                    resource,
                    operation: ops[0].operation,
                },
            });
        }
        return examples;
    }
}
exports.ExampleGenerator = ExampleGenerator;
//# sourceMappingURL=example-generator.js.map