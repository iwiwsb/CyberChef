/**
 * @author iwiwsb [30194859+iwiwsb@users.noreply.github.com]
 * @copyright Crown Copyright 2021
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import { fromHex } from "../lib/Hex.mjs";
import Utils from "../Utils.mjs";
import Stream from "../lib/Stream.mjs";

/**
 * Parse DNS Message operation
 */
class ParseDNS extends Operation {

    /**
     * ParseDNS constructor
     */
    constructor() {
        super();

        this.name = "Parse DNS";
        this.module = "Default";
        this.description = "Parse DNS message";
        this.infoURL = "https://wikipedia.org/wiki/Domain_Name_System";
        this.inputType = "string";
        this.outputType = "JSON";
        // this.presentType = "html";
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
        } else {
            throw new OperationError("Unrecognised input format.");
        }

        const stream = new Stream(new Uint8Array(inputBytes));

        const DomainNameSystemMessage = new Object();
        DomainNameSystemMessage.header = new Object();
        DomainNameSystemMessage.questions = [];
        DomainNameSystemMessage.answers = [];
        DomainNameSystemMessage.authority = [];
        DomainNameSystemMessage.additional = [];


        if (inputBytes.length <= 12) {
            throw new OperationError("Need at least 12 bytes for DNS header");
        }

        DomainNameSystemMessage.header.id = stream.readInt(2);
        // const qrType = `Message is a ${(QR === 0) ? "query" : "response"}`;
        DomainNameSystemMessage.header.messageType = stream.readBits(1);

        const OPCODE = stream.readBits(4);
        // const dnsOperations = [
        //     { opName: "QUERY", opDesc: "A standard query" },          // 0
        //     { opName: "IQUERY", opDesc: "An inverse query" },         // 1
        //     { opName: "STATUS", opDesc: "A server status request" },  // 2
        //     { opName: "Unassigned", opDesc: "" },                     // 3
        //     { opName: "NOTIFY", opDesc: "Zone change notification" }, // 4
        //     { opName: "UPDATE", opDesc: "Dynamic update" },           // 5
        //     { opName: "DSO", opDesc: "DNS Stateful Operations" }      // 6
        // ];
        // let opText= "";
        // if (OPCODE < 7) {
        //     opText = `${dnsOperations[OPCODE].opDesc} (${dnsOperations[OPCODE].opName})`;
        // } else {
        //     opText = "Unknown operation";
        // }

        DomainNameSystemMessage.header.opCode = OPCODE;

        // const authoritativeAnswerDesc = `Server is ${(AA === 0) ? "not " : ""}an authority for domain`;
        DomainNameSystemMessage.header.authoritativeAnswer = stream.readBits(1);

        // const truncationDesc = `Message is ${(TC === 0) ? "not " : ""}truncated`;
        DomainNameSystemMessage.header.truncation = stream.readBits(1);

        const RD = stream.readBits(1);
        // const recursionDesiredDesc = `Do${RD === 1 ? "" : "n't do"} query recursevly`;
        DomainNameSystemMessage.header.recursionDesired = RD;

        const RA = stream.readBits(1);
        // const recursionAvailableDesc = `Server can${(RA === 1) ? "" : "'t"} do recursive queries`;
        DomainNameSystemMessage.header.recursionAvailable = RA;

        const AD = stream.readBits(1);
        // const authenticDataDesc = `Answer/authority portion was ${(AD === 1) ? "" : "not "}authenticated by the server`;
        DomainNameSystemMessage.header.authenticData = AD;

        const CD = stream.readBits(1);
        // const checkDisabled = `Non-authenticated data is ${(CD === 1) ? "" : "not "}acceptable`;
        DomainNameSystemMessage.header.checkDisabled = CD;

        const RCODE = stream.readBits(4);
        DomainNameSystemMessage.header.responseCode = RCODE;

            // Responses 0-5 described in RFC1035
            // Responses 6-10 described in RFC2136
            // Response 11 described in RFC8490
            // Responses 16-18 described in RFC8945
            // Responses 19-21 described in RFC2930
            // Response 22 described in RFC8945
            // Response 23 described in RFC7873
            // const dnsResponses = [
            //     { responseName: "NoError", errorDesc: "No Error" },                          // 0
            //     { responseName: "FormErr", errorDesc: "Format Error" },                      // 1
            //     { responseName: "ServFail", errorDesc: "Server Failure" },                   // 2
            //     { responseName: "NXDomain", errorDesc: "Non-Existent Domain" },              // 3
            //     { responseName: "NotImp", errorDesc: "Not Implemented" },                    // 4
            //     { responseName: "Refused", errorDesc: "Query Refused" },                     // 5
            //     { responseName: "YXDomain", errorDesc: "Name Exists when it should not" },   // 6
            //     { responseName: "YXRRSet", errorDesc: "RR Set Exists when it should not" },  // 7
            //     { responseName: "NXRRSet", errorDesc: "RR Set that should exist does not" }, // 8
            //     { responseName: "NotAuth", errorDesc: "Server Not Authoritative for zone" }, // 9
            //     { responseName: "NotZone", errorDesc: "Name not contained in zone" },        // 10
            //     { responseName: "DSOTYPENI", errorDesc: "DSO-TYPE Not Implemented" },        // 11
            //     { responseName: "Unassigned", errorDesc: "" },                               // 12
            //     { responseName: "Unassigned", errorDesc: "" },                               // 13
            //     { responseName: "Unassigned", errorDesc: "" },                               // 14
            //     { responseName: "Unassigned", errorDesc: "" },                               // 15
            //     { responseName: "BADSIG", errorDesc: "TSIG Signature Failure" },             // 16
            //     { responseName: "BADKEY", errorDesc: "Key not recognized" },                 // 17
            //     { responseName: "BADTIME", errorDesc: "Signature out of time window" },      // 18
            //     { responseName: "BADMODE", errorDesc: "Bad TKEY Mode" },                     // 19
            //     { responseName: "BADNAME", errorDesc: "Duplicate key name" },                // 20
            //     { responseName: "BADALG", errorDesc: "Algorithm not supported" },            // 21
            //     { responseName: "BADTRUNC", errorDesc: "Bad Truncation" },                   // 22
            //     { responseName: "BADCOOKIE", errorDesc: "Bad/missing Server Cookie" },       // 23
            // ];

            // Response described in RFC8945
            // const dnsSecretKeyTransactNotAuthResponse = { responseName: "NotAuth", errorDesc: "Not Authorized" }; // 9

            // Response described in RFC6891
            // const dnsExtensionBadVersResponse = { responseName: "BADVERS", errorDesc: "Bad OPT Version" }; // 16

            // let errorText;
            // errorText = `${dnsResponses[RCODE].errorDesc} (${dnsResponses[RCODE].responseName})`;
            // DomainNameSystemMessage.header.responseCode = `${errorText} (${RCODE})`;


        DomainNameSystemMessage.header.reserved = stream.readBits(1);
        const QDCOUNT = stream.readInt(2);
        const ANCOUNT = stream.readInt(2);
        const NSCOUNT = stream.readInt(2);
        const ARCOUNT = stream.readInt(2);

        DomainNameSystemMessage.header.questionsCount = QDCOUNT;
        DomainNameSystemMessage.header.answersCount = ANCOUNT;
        DomainNameSystemMessage.header.authorityRecordsCount = NSCOUNT;
        DomainNameSystemMessage.header.additionalRecordsCount = ARCOUNT;

        for (let q = 0; q < QDCOUNT; q++) {
            const domain_name_type = stream.readBits(2);
            if (domain_name_type == 0b00) {
                const QuestionSection = new Object();
                let name_len = stream.readBits(6);
                let domain_name_labels = [];
                while (name_len != 0) {
                    domain_name_labels.push(stream.readString(name_len));
                    name_len = stream.readInt(1);
                }
                QuestionSection.QNAME = domain_name_labels.join(".");
                QuestionSection.QTYPE = stream.readInt(2);
                QuestionSection.QCLASS = stream.readInt(2);
                DomainNameSystemMessage.questions.push(QuestionSection);
            } else if (domain_name_type == 0b11) {
                const QuestionSection = new Object();
                const offset = stream.readBits(6);
                const prev_pos = stream.position;
                stream.moveTo(offset);
                stream.readBits(2);
                let name_len = stream.readBits(6);
                let domain_name_labels = [];
                while (name_len != 0) {
                    domain_name_labels.push(stream.readString(name_len));
                    name_len = stream.readInt(1);
                }
                QuestionSection.QNAME = domain_name_labels.join(".");
                QuestionSection.QTYPE = stream.readInt(2);
                QuestionSection.QCLASS = stream.readInt(2);
                stream.moveTo(prev_pos);
            }
            else {
                throw new OperationError("The 10 and 01 combinations of first two bits of label are reserved for future use.")
            }
        }

        for (let an = 0; an < ANCOUNT; an++) {
            // todo
        }

        for (let ns = 0; ns < NSCOUNT; ns++) {
            // todo
        }

        for (let ar = 0; ar < ARCOUNT; ar++) {
            // todo
        }

        return DomainNameSystemMessage;
    }

    // /**
    //  *
    //  */
    // present(dnsMessage) {

    // }

}
export default ParseDNS;

// /**
//  * @private
//  * @param {number} len
//  * @returns {{typeName: string, typeDesc: string}}
//  */
// function generateUnassignedRRTypes(len) {
//     const unassignedTypesArr = [];
//     for (let i = 0; i < len; i++) {
//         unassignedTypesArr.push({ typeName: "Unassigned", typeDesc: "" });
//     }
//     return unassignedTypesArr;
// }


    // static resourceRecordTypes = [
    //     { typeName: "", typeDesc: "" },                                                          // 0
    //     { typeName: "A", typeDesc: "A host address" },                                           // 1
    //     { typeName: "NS", typeDesc: "An authoritative name server" },                            // 2
    //     { typeName: "MD", typeDesc: "A mail destination" },                                      // 3
    //     { typeName: "MF", typeDesc: "A mail forwarder" },                                        // 4
    //     { typeName: "CNAME", typeDesc: "The canonical name for an alias" },                      // 5
    //     { typeName: "SOA", typeDesc: "Marks the start of a zone of authority" },                 // 6
    //     { typeName: "MB", typeDesc: "A mailbox domain name" },                                   // 7
    //     { typeName: "MG", typeDesc: "A mail group member" },                                     // 8
    //     { typeName: "MR", typeDesc: "A mail rename domain name" },                               // 9
    //     { typeName: "NULL", typeDesc: "A null RR" },                                             // 10
    //     { typeName: "WKS", typeDesc: "A well known service description" },                       // 11
    //     { typeName: "PTR", typeDesc: "A domain name pointer" },                                  // 12
    //     { typeName: "HINFO", typeDesc: "Host information" },                                     // 13
    //     { typeName: "MINFO", typeDesc: "Mailbox or mail list information" },                     // 14
    //     { typeName: "MX", typeDesc: "Mail exchange" },                                           // 15
    //     { typeName: "TXT", typeDesc: "Text strings" },                                           // 16
    //     { typeName: "RP", typeDesc: "Responsible Person" },                                      // 17
    //     { typeName: "AFSDB", typeDesc: "AFS Data Base location" },                               // 18
    //     { typeName: "X25", typeDesc: "X.25 PSDN address" },                                      // 19
    //     { typeName: "ISDN", typeDesc: "ISDN address" },                                          // 20
    //     { typeName: "RT", typeDesc: "Route Through" },                                           // 21
    //     { typeName: "NSAP", typeDesc: "NSAP address, NSAP style A record" },                     // 22
    //     { typeName: "NSAP-PTR", typeDesc: "Domain name pointer, NSAP style" },                   // 23
    //     { typeName: "SIG", typeDesc: "Security signature" },                                     // 24
    //     { typeName: "KEY", typeDesc: "Security key" },                                           // 25
    //     { typeName: "PX", typeDesc: "X.400 mail mapping information" },                          // 26
    //     { typeName: "GPOS", typeDesc: "Geographical Position" },                                 // 27
    //     { typeName: "AAAA", typeDesc: "IPv6 Address" },                                          // 28
    //     { typeName: "LOC", typeDesc: "Location Information" },                                   // 29
    //     { typeName: "NXT", typeDesc: "Next Domain (OBSOLETE)" },                                 // 30
    //     { typeName: "EID", typeDesc: "Endpoint Identifier" },                                    // 31
    //     { typeName: "NIMLOC", typeDesc: "Nimrod Locator" },                                      // 32
    //     { typeName: "SRV", typeDesc: "Server Selection" },                                       // 33
    //     { typeName: "ATMA", typeDesc: "ATM Address" },                                           // 34
    //     { typeName: "NAPTR", typeDesc: "Naming Authority Pointer" },                             // 35
    //     { typeName: "KX", typeDesc: "Key Exchanger" },                                           // 36
    //     { typeName: "CERT", typeDesc: "CERT" },                                                  // 37
    //     { typeName: "A6", typeDesc: "A6 (OBSOLETE)" },                                           // 38
    //     { typeName: "DNAME", typeDesc: "DNAME	" },                                             // 39
    //     { typeName: "SINK", typeDesc: "SINK" },                                                  // 40
    //     { typeName: "OPT", typeDesc: "OPT" },                                                    // 41
    //     { typeName: "APL", typeDesc: "APL" },                                                    // 42
    //     { typeName: "DS", typeDesc: "Delegation Signer" },                                       // 43
    //     { typeName: "SSHFP", typeDesc: "SSH Key Fingerprint" },                                  // 44
    //     { typeName: "IPSECKEY", typeDesc: "IPSECKEY" },                                          // 45
    //     { typeName: "RRSIG", typeDesc: "RRSIG" },                                                // 46
    //     { typeName: "NSEC", typeDesc: "NSEC" },                                                  // 47
    //     { typeName: "DNSKEY", typeDesc: "DNSKEY" },                                              // 48
    //     { typeName: "DHCID", typeDesc: "DHCID" },                                                // 49
    //     { typeName: "NSEC3", typeDesc: "NSEC3" },                                                // 50
    //     { typeName: "NSEC3PARAM", typeDesc: "NSEC3PARAM" },                                      // 51
    //     { typeName: "TLSA", typeDesc: "TLSA" },                                                  // 52
    //     { typeName: "SMIMEA", typeDesc: "S/MIME cert association" },                             // 53
    //     { typeName: "Unassigned", typeDesc: "" },                                                // 54
    //     { typeName: "HIP", typeDesc: "Host Identity Protocol" },                                 // 55
    //     { typeName: "NINFO", typeDesc: "NINFO" },                                                // 56
    //     { typeName: "RKEY", typeDesc: "RKEY" },                                                  // 57
    //     { typeName: "TALINK", typeDesc: "Trust Anchor LINK" },                                   // 58
    //     { typeName: "CDS", typeDesc: "Child DS" },                                               // 59
    //     { typeName: "CDNSKEY", typeDesc: "DNSKEY(s) the Child wants reflected in DS" },          // 60
    //     { typeName: "OPENPGPKEY", typeDesc: "OpenPGP Key" },                                     // 61
    //     { typeName: "CSYNC", typeDesc: "Child-To-Parent Synchronization" },                      // 62
    //     { typeName: "ZONEMD", typeDesc: "Message Digest Over Zone Data" },                       // 63
    //     { typeName: "SVCB", typeDesc: "Service Binding" },                                       // 64
    //     { typeName: "HTTPS", typeDesc: "HTTPS Binding" },                                        // 65
    //     ...generateUnassignedRRTypes(34),                                                        // 66-98
    //     { typeName: "SPF", typeDesc: "" },                                                       // 99
    //     { typeName: "UINFO", typeDesc: "" },                                                     // 100
    //     { typeName: "UID", typeDesc: "" },                                                       // 101
    //     { typeName: "GID", typeDesc: "" },                                                       // 102
    //     { typeName: "UNSPEC", typeDesc: "" },                                                    // 103
    //     { typeName: "NID", typeDesc: "" },                                                       // 104
    //     { typeName: "L32", typeDesc: "" },                                                       // 105
    //     { typeName: "L64", typeDesc: "" },                                                       // 106
    //     { typeName: "LP", typeDesc: "" },                                                        // 107
    //     { typeName: "EUI48", typeDesc: "EUI-48 address" },                                       // 108
    //     { typeName: "EUI64", typeDesc: "EUI-64 address" },                                       // 109
    //     ...generateUnassignedRRTypes(139),                                                       // 110-248
    //     { typeName: "TKEY", typeDesc: "Transaction Key" },                                       // 249
    //     { typeName: "TSIG", typeDesc: "Transaction Signature" },                                 // 250
    //     { typeName: "IXFR", typeDesc: "Incremental transfer" },                                  // 251
    //     { typeName: "AXFR", typeDesc: "A request for a transfer of an entire zone" },            // 252
    //     { typeName: "MAILB", typeDesc: "A request for mailbox-related records (MB, MG or MR)" }, // 253
    //     { typeName: "MAILA", typeDesc: "A request for mail agent RRs (Obsolete - see MX)" },     // 254
    //     { typeName: "*", typeDesc: "A request for all records" },                                // 255
    // ];

    // resourceRecordClasses = [
    //     { className: "", classDesc: "" },                                                                        // 0
    //     { className: "IN", classDesc: "Internet" },                                                              // 1
    //     { className: "CS", classDesc: "CSNET class (Obsolete - used only for examples in some obsolete RFCs)" }, // 2
    //     { className: "CH", classDesc: "CHAOS class" },                                                           // 3
    //     { className: "HS", classDesc: "Hesiod [Dyer 87]" },                                                      // 4
    // ];
