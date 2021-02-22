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

        const resourseRecordTypes = [
            { typeName: "", typeDesc: "" },                                                          // 0
            { typeName: "A", typeDesc: "A host address" },                                           // 1
            { typeName: "NS", typeDesc: "An authoritative name server" },                            // 2
            { typeName: "MD", typeDesc: "A mail destination" },                                      // 3
            { typeName: "MF", typeDesc: "A mail forwarder" },                                        // 4
            { typeName: "CNAME", typeDesc: "The canonical name for an alias" },                      // 5
            { typeName: "SOA", typeDesc: "Marks the start of a zone of authority" },                 // 6
            { typeName: "MB", typeDesc: "A mailbox domain name" },                                   // 7
            { typeName: "MG", typeDesc: "A mail group member" },                                     // 8
            { typeName: "MR", typeDesc: "A mail rename domain name" },                               // 9
            { typeName: "NULL", typeDesc: "A null RR" },                                             // 10
            { typeName: "WKS", typeDesc: "A well known service description" },                       // 11
            { typeName: "PTR", typeDesc: "A domain name pointer" },                                  // 12
            { typeName: "HINFO", typeDesc: "Host information" },                                     // 13
            { typeName: "MINFO", typeDesc: "Mailbox or mail list information" },                     // 14
            { typeName: "MX", typeDesc: "Mail exchange" },                                           // 15
            { typeName: "TXT", typeDesc: "Text strings" },                                           // 16
            { typeName: "RP", typeDesc: "Responsible Person" },                                      // 17
            { typeName: "AFSDB", typeDesc: "AFS Data Base location" },                               // 18
            { typeName: "X25", typeDesc: "X.25 PSDN address" },                                      // 19
            { typeName: "ISDN", typeDesc: "ISDN address" },                                          // 20
            { typeName: "RT", typeDesc: "Route Through" },                                           // 21
            { typeName: "NSAP", typeDesc: "NSAP address, NSAP style A record" },                     // 22
            { typeName: "NSAP-PTR", typeDesc: "Domain name pointer, NSAP style" },                   // 23
            { typeName: "SIG", typeDesc: "Security signature" },                                     // 24
            { typeName: "KEY", typeDesc: "Security key" },                                           // 25
            { typeName: "PX", typeDesc: "X.400 mail mapping information" },                          // 26
            { typeName: "GPOS", typeDesc: "Geographical Position" },                                 // 27
            { typeName: "AAAA", typeDesc: "IPv6 Address" },                                          // 28
            { typeName: "LOC", typeDesc: "Location Information" },                                   // 29
            { typeName: "NXT", typeDesc: "Next Domain (OBSOLETE)" },                                 // 30
            { typeName: "EID", typeDesc: "Endpoint Identifier" },                                    // 31
            { typeName: "NIMLOC", typeDesc: "Nimrod Locator" },                                      // 32
            { typeName: "SRV", typeDesc: "Server Selection" },                                       // 33
            { typeName: "ATMA", typeDesc: "ATM Address" },                                           // 34
            { typeName: "NAPTR", typeDesc: "Naming Authority Pointer" },                             // 35
            { typeName: "KX", typeDesc: "Key Exchanger" },                                           // 36
            { typeName: "CERT", typeDesc: "CERT" },                                                  // 37
            { typeName: "A6", typeDesc: "A6 (OBSOLETE)" },                                           // 38
            { typeName: "DNAME", typeDesc: "DNAME	" },                                             // 39
            { typeName: "SINK", typeDesc: "SINK" },                                                  // 40
            { typeName: "OPT", typeDesc: "OPT" },                                                    // 41
            { typeName: "APL", typeDesc: "APL" },                                                    // 42
            { typeName: "DS", typeDesc: "Delegation Signer" },                                       // 43
            { typeName: "SSHFP", typeDesc: "SSH Key Fingerprint" },                                  // 44
            { typeName: "IPSECKEY", typeDesc: "IPSECKEY" },                                          // 45
            { typeName: "RRSIG", typeDesc: "RRSIG" },                                                // 46
            { typeName: "NSEC", typeDesc: "NSEC" },                                                  // 47
            { typeName: "DNSKEY", typeDesc: "DNSKEY" },                                              // 48
            { typeName: "DHCID", typeDesc: "DHCID" },                                                // 49
            { typeName: "NSEC3", typeDesc: "NSEC3" },                                                // 50
            { typeName: "NSEC3PARAM", typeDesc: "NSEC3PARAM" },                                      // 51
            { typeName: "TLSA", typeDesc: "TLSA" },                                                  // 52
            { typeName: "SMIMEA", typeDesc: "S/MIME cert association" },                             // 53
            { typeName: "Unassigned", typeDesc: "" },                                                // 54
            { typeName: "HIP", typeDesc: "Host Identity Protocol" },                                 // 55
            { typeName: "NINFO", typeDesc: "NINFO" },                                                // 56
            { typeName: "RKEY", typeDesc: "RKEY" },                                                  // 57
            { typeName: "TALINK", typeDesc: "Trust Anchor LINK" },                                   // 58
            { typeName: "CDS", typeDesc: "Child DS" },                                               // 59
            { typeName: "CDNSKEY", typeDesc: "DNSKEY(s) the Child wants reflected in DS" },          // 60
            { typeName: "OPENPGPKEY", typeDesc: "OpenPGP Key" },                                     // 61
            { typeName: "CSYNC", typeDesc: "Child-To-Parent Synchronization" },                      // 62
            { typeName: "ZONEMD", typeDesc: "Message Digest Over Zone Data" },                       // 63
            { typeName: "SVCB", typeDesc: "Service Binding" },                                       // 64
            { typeName: "HTTPS", typeDesc: "HTTPS Binding" },                                        // 65
            ...generateUnassignedRRTypes(34),                                                        // 66-98
            { typeName: "SPF", typeDesc: "" },                                                       // 99
            { typeName: "UINFO", typeDesc: "" },                                                     // 100
            { typeName: "UID", typeDesc: "" },                                                       // 101
            { typeName: "GID", typeDesc: "" },                                                       // 102
            { typeName: "UNSPEC", typeDesc: "" },                                                    // 103
            { typeName: "NID", typeDesc: "" },                                                       // 104
            { typeName: "L32", typeDesc: "" },                                                       // 105
            { typeName: "L64", typeDesc: "" },                                                       // 106
            { typeName: "LP", typeDesc: "" },                                                        // 107
            { typeName: "EUI48", typeDesc: "EUI-48 address" },                                       // 108
            { typeName: "EUI64", typeDesc: "EUI-64 address" },                                       // 109
            ...generateUnassignedRRTypes(139),                                                       // 110-248
            { typeName: "TKEY", typeDesc: "Transaction Key" },                                       // 249
            { typeName: "TSIG", typeDesc: "Transaction Signature" },                                 // 250
            { typeName: "IXFR", typeDesc: "Incremental transfer" },                                  // 251
            { typeName: "AXFR", typeDesc: "A request for a transfer of an entire zone" },            // 252
            { typeName: "MAILB", typeDesc: "A request for mailbox-related records (MB, MG or MR)" }, // 253
            { typeName: "MAILA", typeDesc: "A request for mail agent RRs (Obsolete - see MX)" },     // 254
            { typeName: "*", typeDesc: "A request for all records" },                                // 255
        ];

        const resourseRecordClasses = [
            { className: "", classDesc: "" },                                                                        // 0
            { className: "IN", classDesc: "Internet" },                                                              // 1
            { className: "CS", classDesc: "CSNET class (Obsolete - used only for examples in some obsolete RFCs)" }, // 2
            { className: "CH", classDesc: "CHAOS class" },                                                           // 3
            { className: "HS", classDesc: "Hesiod [Dyer 87]" },                                                      // 4
        ];

        const DomainNameSystemMessage = new Object();
        DomainNameSystemMessage.header = new Object();
        DomainNameSystemMessage.question = [];
        DomainNameSystemMessage.answer = [];
        DomainNameSystemMessage.authority = [];
        DomainNameSystemMessage.additional = [];


        if (inputBytes.length < 12) {
            throw new OperationError("Need 12 bytes for a DNS Message Header");
        }

        DomainNameSystemMessage.header.id = inputBytes[0] * 0x100 + inputBytes[1];

        const QR = inputBytes[2] >> 7;
        const qrType = `Message is a ${(QR === 0) ? "query" : "response"}`;
        DomainNameSystemMessage.header.messageType = `${qrType} (${QR})`;

        const OPCODE = (inputBytes[2] >> 3) & 0b1111;
        const dnsOperations = [
            { opName: "QUERY", opDesc: "A standard query" },          // 0
            { opName: "IQUERY", opDesc: "An inverse query" },         // 1
            { opName: "STATUS", opDesc: "A server status request" },  // 2
            { opName: "Unassigned", opDesc: "" },                     // 3
            { opName: "NOTIFY", opDesc: "Zone change notification" }, // 4
            { opName: "UPDATE", opDesc: "Dynamic update" },           // 5
            { opName: "DSO", opDesc: "DNS Stateful Operations" }      // 6
        ];
        let opText;
        if (OPCODE < 7) {
            opText = `${dnsOperations[OPCODE].opDesc} (${dnsOperations[OPCODE].opName})`;
        } else {
            opText = "Unknown operation";
        }
        DomainNameSystemMessage.header.opCode = `${opText} (${OPCODE})`;

        const TC = (inputBytes[2] >> 1) & 1;
        const truncationDesc = `Message is ${(TC === 0) ? "not " : ""}truncated`;
        DomainNameSystemMessage.header.truncation = `${truncationDesc} (${TC})`;

        const RD = inputBytes[2] & 1;
        const recursionDesiredDesc = `Do${RD === 1 ? "" : "n't do"} query recursevly`;
        DomainNameSystemMessage.header.recursionDesired = `${recursionDesiredDesc} (${RD})`;

        // True only for response messages
        if (QR === 1) {
            const AA = (inputBytes[2] >> 2) & 1;
            const authoritativeAnswerDesc = `Server is ${(AA === 0) ? "not " : ""}an authority for domain`;
            DomainNameSystemMessage.header.authoritativeAnswer = `${authoritativeAnswerDesc} (${AA})`;

            const RA = inputBytes[3] >> 7;
            const recursionAvailableDesc = `Server can${(RA === 1) ? "" : "'t"} do recursive queries`;
            DomainNameSystemMessage.header.recursionAvailable = `${recursionAvailableDesc} (${RA})`;

            const AD = (inputBytes[3] >> 5) & 1;
            const authenticDataDesc = `Answer/authority portion was ${(AD === 1) ? "" : "not "}authenticated by the server`;
            DomainNameSystemMessage.header.authenticData = `${authenticDataDesc} (${AD})`;

            const CD = (inputBytes[3] >> 4) & 1;
            const checkDisabled = `Non-authenticated data is ${(CD === 1) ? "" : "not "}acceptable`;
            DomainNameSystemMessage.header.checkDisabled = `${checkDisabled} (${CD})`;

            const RCODE = inputBytes[3] & 0b1111;

            // Responses 0-5 described in RFC1035
            // Responses 6-10 described in RFC2136
            // Response 11 described in RFC8490
            // Responses 16-18 described in RFC8945
            // Responses 19-21 described in RFC2930
            // Response 22 described in RFC8945
            // Response 23 described in RFC7873
            const dnsResponses = [
                { responseName: "NoError", errorDesc: "No Error" },                          // 0
                { responseName: "FormErr", errorDesc: "Format Error" },                      // 1
                { responseName: "ServFail", errorDesc: "Server Failure" },                   // 2
                { responseName: "NXDomain", errorDesc: "Non-Existent Domain" },              // 3
                { responseName: "NotImp", errorDesc: "Not Implemented" },                    // 4
                { responseName: "Refused", errorDesc: "Query Refused" },                     // 5
                { responseName: "YXDomain", errorDesc: "Name Exists when it should not" },   // 6
                { responseName: "YXRRSet", errorDesc: "RR Set Exists when it should not" },  // 7
                { responseName: "NXRRSet", errorDesc: "RR Set that should exist does not" }, // 8
                { responseName: "NotAuth", errorDesc: "Server Not Authoritative for zone" }, // 9
                { responseName: "NotZone", errorDesc: "Name not contained in zone" },        // 10
                { responseName: "DSOTYPENI", errorDesc: "DSO-TYPE Not Implemented" },        // 11
                { responseName: "Unassigned", errorDesc: "" },                               // 12
                { responseName: "Unassigned", errorDesc: "" },                               // 13
                { responseName: "Unassigned", errorDesc: "" },                               // 14
                { responseName: "Unassigned", errorDesc: "" },                               // 15
                { responseName: "BADSIG", errorDesc: "TSIG Signature Failure" },             // 16
                { responseName: "BADKEY", errorDesc: "Key not recognized" },                 // 17
                { responseName: "BADTIME", errorDesc: "Signature out of time window" },      // 18
                { responseName: "BADMODE", errorDesc: "Bad TKEY Mode" },                     // 19
                { responseName: "BADNAME", errorDesc: "Duplicate key name" },                // 20
                { responseName: "BADALG", errorDesc: "Algorithm not supported" },            // 21
                { responseName: "BADTRUNC", errorDesc: "Bad Truncation" },                   // 22
                { responseName: "BADCOOKIE", errorDesc: "Bad/missing Server Cookie" },       // 23
            ];

            // Response described in RFC8945
            const dnsSecretKeyTransactNotAuthResponse = { responseName: "NotAuth", errorDesc: "Not Authorized" }; // 9

            // Response described in RFC6891
            const dnsExtensionBadVersResponse = { responseName: "BADVERS", errorDesc: "Bad OPT Version" }; // 16

            let errorText;
            if (RCODE < 24) {
                errorText = `${dnsResponses[RCODE].errorDesc} (${dnsResponses[RCODE].responseName})`;
            } else if (RCODE >= 24 && RCODE < 3840 || RCODE >= 4096 && RCODE <= 65534) {
                errorText = "No error assigned to this code";
            } else if (RCODE >= 3841 && RCODE <= 4095) {
                errorText = "Error code reserved for private use";
            }
            DomainNameSystemMessage.header.responseCode = `${errorText} (${RCODE})`;
        }

        DomainNameSystemMessage.header.Z = (inputBytes[3] >> 6) & 1;
        const QDCOUNT = inputBytes[4] * 0x100 + inputBytes[5];
        const ANCOUNT = inputBytes[6] * 0x100 + inputBytes[7];
        const NSCOUNT = inputBytes[8] * 0x100 + inputBytes[9];
        const ARCOUNT = inputBytes[10] * 0x100 + inputBytes[11];

        DomainNameSystemMessage.header.questionsCount = QDCOUNT;
        DomainNameSystemMessage.header.answersCount = ANCOUNT;
        DomainNameSystemMessage.header.authorityRecordsCount = NSCOUNT;
        DomainNameSystemMessage.header.additionalRecordsCount = ARCOUNT;

        let offset = 12;

        for (let q = 0; q < QDCOUNT; q++) {
            const domain = parseDomainName({name: "", nextLabelOffset: offset }, inputBytes);
            const QNAME = domain.name;
            offset += domain.nextLabelOffset;
            const QTYPE = inputBytes[offset] * 0x100 + inputBytes[offset += 1];
            const QCLASS = inputBytes[offset] * 0x100 + inputBytes[offset += 1];

            DomainNameSystemMessage.question.push(new Question(QNAME, QTYPE, QCLASS));
        }

        const output = DomainNameSystemMessage;
        return output;
    }

}

/**
 * @private
 * @param {number} len
 * @returns {{typeName: string, typeDesc: string}}
 */
function generateUnassignedRRTypes(len) {
    const unassignedTypesArr = [];
    for (let i = 0; i < len; i++) {
        unassignedTypesArr.push({ typeName: "Unassigned", typeDesc: "" });
    }
    return unassignedTypesArr;
}

/**
 * @private
 * @param {{name: string, nextLabelOffset: number}} domain
 * @param {number[]} inputBytes
 * @returns {{name: string, nextLabelOffset: number}}
 */
function parseDomainName(domain, inputBytes) {
    let domainName = domain.name;
    if (inputBytes[domain.nextLabelOffset] !== 0) {
        switch (inputBytes[domain.nextLabelOffset] >> 6) {
            case 0:
                domainName += inputBytes.slice(domain.nextLabelOffset + 1, inputBytes[domain.nextLabelOffset]).map(x => fromHex(x)).join("");
                domainName += ".";
                domain += parseDomainName({ name: domainName, nextLabelOffset: domainName.length + 1 }, inputBytes);
                break;
            case 0b11:
                domain += parseDomainName({ name: domainName, nextLabelOffset: domain.nextLabelOffset + 1 }, inputBytes);
                break;
            default:
                break;
        }
    }
    return domain;
}

/**
 * Class for Question structure
 * @private
 */
class Question {
    /**
     * Question structure constructor
     * @param {string} questionName
     * @param {number} questionType
     * @param {number} questionClass
     */
    constructor(questionName, questionType, questionClass) {
        this.questionName = questionName;
        this.questionType = questionType;
        this.questionClass = questionClass;
    }
}

/**
 * Class for Resourse Record structure
 * @private
 */
class ResourceRecord {
    /**
     * Resourse Record structure constructor
     * @param name
     * @param type
     * @param dataClass
     * @param timeToLive
     * @param resourseDataLength
     * @param resourseData
     */
    constructor(name, type, dataClass, timeToLive, resourseDataLength, resourseData) {
        this.name = name;
        this.type = type;
        this.dataClass = dataClass;
        this.timeToLive = timeToLive;
        this.resourseDataLength = resourseDataLength;
        this.resourseData = resourseData;
    }
}

export default ParseDNSMessage;