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

        /**
         * Class for Resourse Record structure
         */
        class ResourceRecord {
            /**
             * Resourse Record structure constructor
             */
            constructor(name, type, dataClass, timeToLive, resourseDataLength, resourseData) {
                this.type = type;
                this.dataClass = dataClass;
                this.timeToLive = timeToLive;
                this.resourseDataLength = resourseDataLength;
                this.resourseData = resourseData;
            }
        }

        const DomainNameSystemMessage = new Object();
        DomainNameSystemMessage.Header = new Object();
        DomainNameSystemMessage.Question = new Object();
        DomainNameSystemMessage.Answer = new ResourceRecord();


        if (inputBytes.length < 12) {
            throw new OperationError("Need 12 bytes for a DNS Message Header");
        }

        DomainNameSystemMessage.Header.id = inputBytes[0] * 0x100 + inputBytes[1];

        const QR = inputBytes[2] >> 7;
        const qrType = `Message is a ${(QR === 0) ? "query" : "response"}`;
        DomainNameSystemMessage.Header.messageType = `${qrType} (${QR})`;

        const OPCODE = (inputBytes[2] >> 3) & 0b1111;
        const dnsOperations = [
            {opName: "QUERY",      opDesc: "A standard query"},         // 0
            {opName: "IQUERY",     opDesc: "An inverse query"},         // 1
            {opName: "STATUS",     opDesc: "A server status request"},  // 2
            {opName: "Unassigned", opDesc: ""},                         // 3
            {opName: "NOTIFY",     opDesc: "Zone change notification"}, // 4
            {opName: "UPDATE",     opDesc: "Dynamic update"},           // 5
            {opName: "DSO",        opDesc: "DNS Stateful Operations"}   // 6
        ];
        let opText;
        if (OPCODE < 7) {
            opText = `${dnsOperations[OPCODE].opDesc} (${dnsOperations[OPCODE].opName})`;
        } else {
            opText = "Unknown operation";
        }
        DomainNameSystemMessage.Header.opCode = `${opText} (${OPCODE})`;

        const TC = (inputBytes[2] >> 1) & 1;
        const truncationDesc = `Message is ${(TC === 0) ? "not " : ""}truncated`;
        DomainNameSystemMessage.Header.truncation = `${truncationDesc} (${TC})`;

        const RD = inputBytes[2] & 1;
        const recursionDesiredDesc = `Do${RD === 1 ? "" : "n't do"} query recursevly`;
        DomainNameSystemMessage.Header.recursionDesired = `${recursionDesiredDesc} (${RD})`;

        // True only for response messages
        if (QR === 1) {
            const AA = (inputBytes[2] >> 2) & 1;
            const authoritativeAnswerDesc = `Server is ${(AA === 0) ? "not " : ""}an authority for domain`;
            DomainNameSystemMessage.Header.authoritativeAnswer = `${authoritativeAnswerDesc} (${AA})`;

            const RA = inputBytes[3] >> 7;
            const recursionAvailableDesc = `Server can${(RA === 1) ? "" : "'t"} do recursive queries`;
            DomainNameSystemMessage.Header.recursionAvailable = `${recursionAvailableDesc} (${RA})`;

            const AD = (inputBytes[3] >> 5) & 1;
            const authenticDataDesc = `Answer/authority portion was ${(AD === 1) ? "" : "not "}authenticated by the server`;
            DomainNameSystemMessage.Header.authenticData = `${authenticDataDesc} (${AD})`;

            const CD = (inputBytes[3] >> 4) & 1;
            const checkDisabled = `Non-authenticated data is ${(CD === 1) ? "" : "not "}acceptable`;
            DomainNameSystemMessage.Header.checkDisabled = `${checkDisabled} (${CD})`;

            const RCODE = inputBytes[3] & 0b1111;

            // Responses 0-5 described in RFC1035
            // Responses 6-10 described in RFC2136
            // Response 11 described in RFC8490
            // Responses 16-18 described in RFC8945
            // Responses 19-21 described in RFC2930
            // Response 22 described in RFC8945
            // Response 23 described in RFC7873
            const dnsResponses = [
                {responseName: "NoError",    errorDesc: "No Error"},                          // 0
                {responseName: "FormErr",    errorDesc: "Format Error"},                      // 1
                {responseName: "ServFail",   errorDesc: "Server Failure"},                    // 2
                {responseName: "NXDomain",   errorDesc: "Non-Existent Domain"},               // 3
                {responseName: "NotImp",     errorDesc: "Not Implemented"},                   // 4
                {responseName: "Refused",    errorDesc: "Query Refused"},                     // 5
                {responseName: "YXDomain",   errorDesc: "Name Exists when it should not"},    // 6
                {responseName: "YXRRSet",    errorDesc: "RR Set Exists when it should not"},  // 7
                {responseName: "NXRRSet",    errorDesc: "RR Set that should exist does not"}, // 8
                {responseName: "NotAuth",    errorDesc: "Server Not Authoritative for zone"}, // 9
                {responseName: "NotZone",    errorDesc: "Name not contained in zone"},        // 10
                {responseName: "DSOTYPENI",  errorDesc: "DSO-TYPE Not Implemented"},          // 11
                {responseName: "Unassigned", errorDesc: ""},                                  // 12
                {responseName: "Unassigned", errorDesc: ""},                                  // 13
                {responseName: "Unassigned", errorDesc: ""},                                  // 14
                {responseName: "Unassigned", errorDesc: ""},                                  // 15
                {responseName: "BADSIG",     errorDesc: "TSIG Signature Failure"},            // 16
                {responseName: "BADKEY",     errorDesc: "Key not recognized"},                // 17
                {responseName: "BADTIME",    errorDesc: "Signature out of time window"},      // 18
                {responseName: "BADMODE",    errorDesc: "Bad TKEY Mode"},                     // 19
                {responseName: "BADNAME",    errorDesc: "Duplicate key name"},                // 20
                {responseName: "BADALG",     errorDesc: "Algorithm not supported"},           // 21
                {responseName: "BADTRUNC",   errorDesc: "Bad Truncation"},                    // 22
                {responseName: "BADCOOKIE",  errorDesc: "Bad/missing Server Cookie"},         // 23
            ];

            // Response described in RFC8495
            const dnsUpdateNotAuthResponse = {responseName: "NotAuth", errorDesc: "Not Authorized"}; // 9

            // Response described in RFC6891
            const dnsExtensionBadVersResponse = {responseName: "BADVERS",  errorDesc: "Bad OPT Version"}; // 16

            let errorText;
            if (RCODE < 24) {
                errorText = `${dnsResponses[RCODE].errorDesc} (${dnsResponses[RCODE].responseName})`;
            } else if (RCODE >= 24 && RCODE < 3840 || RCODE >= 4096 && RCODE <= 65534) {
                errorText = "No error assigned to this code";
            } else if (RCODE >= 3841 && RCODE <= 4095) {
                errorText = "Error code reserved for private use";
            }
            DomainNameSystemMessage.Header.responseCode = `${errorText} (${RCODE})`;
        }

        DomainNameSystemMessage.Header.Z = (inputBytes[3] >> 6) & 1;
        DomainNameSystemMessage.Header.QDCOUNT = inputBytes[4] * 0x100 + inputBytes[5];
        DomainNameSystemMessage.Header.ANCOUNT = inputBytes[6] * 0x100 + inputBytes[7];
        DomainNameSystemMessage.Header.NSCOUNT = inputBytes[8] * 0x100 + inputBytes[9];
        DomainNameSystemMessage.Header.ARCOUNT = inputBytes[10] * 0x100 + inputBytes[11];

        const output = DomainNameSystemMessage;
        return output;
    }

}

export default ParseDNSMessage;
