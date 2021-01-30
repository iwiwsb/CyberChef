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
        this.outputType = "JSON";
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
     * @returns {JSON}
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

        if (inputBytes.length < 12) {
            throw new OperationError("Need 12 bytes for a DNS Message Header");
        }

        dnsMessage.Header.ID = inputBytes[0] * 0x100 + inputBytes[1];

        const QR = inputBytes[2] >> 7;
        let qrType = "";
        switch (QR) {
            case 0:
                qrType = "Message is a query";
                break;
            case 1:
                qrType = "Message is a response";
                break;
            default:
                qrType = "Invalid message type";
        }
        dnsMessage.Header.QR = `${qrType} (${QR})`;

        const OPCODE = (inputBytes[2] >> 3) & 0b1111;
        const dnsOperations = [
            {opName: "QUERY",  opDesc: "A standard query"},         // 0
            {opName: "IQUERY", opDesc: "An inverse query"},         // 1
            {opName: "STATUS", opDesc: "A server status request"},  // 2
            {opName: "NOTIFY", opDesc: "Zone change notification"}, // 3
            {opName: "DSO",    opDesc: "DNS Stateful Operations"}   // 4
        ];
        let opText;
        if (OPCODE < 7) {
            opText = `${dnsOperations[OPCODE].opName} - ${dnsOperations[OPCODE].opDesc}`;
        } else {
            opText = "Unknown operation";
        }
        dnsMessage.Header.OPCODE = `${opText} (${OPCODE})`;

        const TC = (inputBytes[2] >> 1) & 1;
        const isTruncated = `Message is ${(TC === 0) ? "not " : ""}truncated`;
        dnsMessage.Header.TC = `${isTruncated} (${TC})`;

        const RD = inputBytes[2] & 1;
        const isRecursionDesired = `Do${RD === 1 ? "" : "n't do"} query recursevly`;
        dnsMessage.Header.RD = `${isRecursionDesired} (${RD})`;

        if (QR === 1) {
            const AA = (inputBytes[2] >> 2) & 1;
            const isAuthoritativeAnswer = `Server is ${(AA === 0) ? "not " : ""}an authority for domain`;
            dnsMessage.Header.AA = `${isAuthoritativeAnswer} (${AA})`;

            const RA = inputBytes[3] >> 7;
            const isRecursionAvailable = `Server can${(RA === 1) ? "" : "'t"} do recursive queries`;
            dnsMessage.Header.RA = `${isRecursionAvailable} (${RA})`;

            const AD = (inputBytes[3] >> 5) & 1;
            const isAuthenticated = `Answer/authority portion was ${(AD === 1) ? "" : "not "}authenticated by the server`;
            dnsMessage.Header.AD = `${isAuthenticated} (${AD})`;

            const CD = (inputBytes[3] >> 4) & 1;
            const isCheckDisabled = `Non-authenticated data is ${(CD === 1) ? "" : "not "}acceptable`;
            dnsMessage.Header.CD = `${isCheckDisabled} (${CD})`;
        }

        dnsMessage.Header.Z = (inputBytes[3] >> 6) & 1;

        const errorCode = inputBytes[3] & 0b1111;
        const dnsErrors = [
            {errorName: "NoError",    errorDesc: "No Error"},                                           // 0
            {errorName: "FormErr",    errorDesc: "Format Error"},                                       // 1
            {errorName: "ServFail",   errorDesc: "Server Failure"},                                     // 2
            {errorName: "NXDomain",   errorDesc: "Non-Existent Domain"},                                // 3
            {errorName: "NotImp",     errorDesc: "Not Implemented"},                                    // 4
            {errorName: "Refused",    errorDesc: "Query Refused"},                                      // 5
            {errorName: "YXDomain",   errorDesc: "Name Exists when it should not"},                     // 6
            {errorName: "YXRRSet",    errorDesc: "RR Set Exists when it should not"},                   // 7
            {errorName: "NXRRSet",    errorDesc: "RR Set that should exist does not"},                  // 8
            {errorName: "NotAuth",    errorDesc: "Server Not Authoritative for zone / Not Authorized"}, // 9
            {errorName: "NotZone",    errorDesc: "Name not contained in zone"},                         // 10
            {errorName: "DSOTYPENI",  errorDesc: "DSO-TYPE Not Implemented"},                           // 11
            {errorName: "Unassigned", errorDesc: ""},                                                   // 12
            {errorName: "Unassigned", errorDesc: ""},                                                   // 13
            {errorName: "Unassigned", errorDesc: ""},                                                   // 14
            {errorName: "Unassigned", errorDesc: ""},                                                   // 15
            {errorName: "BADVERS",    errorDesc: "Bad OPT Version / TSIG Signature Failure"},           // 16
            {errorName: "BADKEY",     errorDesc: "Key not recognized"},                                 // 17
            {errorName: "BADTIME",    errorDesc: "Signature out of time window"},                       // 18
            {errorName: "BADMODE",    errorDesc: "Bad TKEY Mode"},                                      // 19
            {errorName: "BADNAME",    errorDesc: "Duplicate key name"},                                 // 20
            {errorName: "BADALG",     errorDesc: "Algorithm not supported"},                            // 21
            {errorName: "BADTRUNC",   errorDesc: "Bad Truncation"},                                     // 22
            {errorName: "BADCOOKIE",  errorDesc: "Bad/missing Server Cookie"}                           // 23
        ];
        let errorText;
        if (errorCode < 24) {
            errorText = `${dnsErrors[errorCode].errorName} - ${dnsErrors[errorCode].errorDesc}`;
        } else if (errorCode >= 24 && errorCode < 3840 || errorCode >= 4096 && errorCode <= 65534) {
            errorText = "No error assigned to this code";
        } else if (errorCode >= 3841 && errorCode <= 4095) {
            errorText = "Error code reserved for private use";
        }
        dnsMessage.Header.RCODE = `${errorText} (${errorCode})`;

        dnsMessage.Header.QDCOUNT = inputBytes[4] * 0x100 + inputBytes[5];
        dnsMessage.Header.ANCOUNT = inputBytes[6] * 0x100 + inputBytes[7];
        dnsMessage.Header.NSCOUNT = inputBytes[8] * 0x100 + inputBytes[9];
        dnsMessage.Header.ARCOUNT = inputBytes[10] * 0x100 + inputBytes[11];

        const output = dnsMessage;
        return output;
    }

}

export default ParseDNSMessage;
