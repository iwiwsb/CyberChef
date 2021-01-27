/**
 * @author iwiwsb [30194859+iwiwsb@users.noreply.github.com]
 * @copyright Crown Copyright 2021
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import { fromHex } from "../lib/Hex.mjs";
import Utils from "../Utils.mjs";

/**
 * Parse DNS Message operation
 */
class ParseDNSMessage extends Operation {

    /**
     * ParseDNSMessage constructor
     */
    constructor() {
        super();

        this.name = "Parse DNS Message";
        this.module = "Default";
        this.description = "Parse DNS message";
        this.infoURL = "https://wikipedia.org/wiki/Domain_Name_System";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                "name": "Input format",
                "type": "option",
                "value": ["Hex", "Raw"]
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const format = args[0];

        let inputBytes = [];
        if (format === "Hex") {
            inputBytes = fromHex(input);
        } else if (format === "Raw") {
            inputBytes = Utils.strToByteArray(input);
        }

        const dnsMessage = new Object();
        dnsMessage.Header = new Object();

        const inputBytesLength = inputBytes.length;

        if (inputBytesLength < 12) {
            throw new OperationError("Need 12 bytes for a DNS Message Header");
        }

        dnsMessage.Header.ID = inputBytes[0] * 0x16 + inputBytes[1];

        dnsMessage.Header.QR = input[2] >> 7;
        let qrType = "";
        switch (dnsMessage.Header.QR) {
            case 0:
                qrType = "Message is a query";
                break;
            case 1:
                qrType = "Message is a response";
                break;
            default:
                throw new OperationError("Invalid message type");
        }

        dnsMessage.Header.opcode = (input[3] & 0b01111000) >> 3;
        let opType = "";
        switch (dnsMessage.Header.opcode) {
            case 0:
                opType = "QUERY: a standard query";
                break;
            case 1:
                opType = "IQUERY: an inverse query";
                break;
            case 2:
                opType = "STATUS: a server status request";
                break;
            default:
                throw new OperationError("Invalid opcode. Values 3-15 reserved for future use");
        }

        const output = `Identifier: ${dnsMessage.Header.ID}
Query type: ${dnsMessage.Header.QR.toString()} (${qrType})
Opcode: ${dnsMessage.Header.opcode} (${opType})`;

        return output;
    }

}

export default ParseDNSMessage;
