// Jason Vermillion
// 04/24/2019

var fs = require('fs');

// Get filename arg
var args = [];
process.argv.forEach(function (val, index, array) {
    if (index === 2) args.push(val);
});

// Generate filenames
var fileName = args[0];
var fileNameTxt = fileName + '.txt';
var fileNameJSON = fileName + '-links.json';

// Get date
function getDate (dateString) {
    var year = dateString.substring(0, 4);
    var month = dateString.substring(4, 6);
    var day = dateString.substring(6, 8);
    return year + '-' + month + '-' + day;
}

dataDate = getDate(fileName);

// Read data file and parse to JSON
fs.readFile(fileNameTxt, (err, data) => {
    if (err) throw err; 
    // Main Node
    var dataString = '{\"nodeType\": \"main\", \"id\": \"MainCluster\", \"name\": \"Kyoto University Honeypot Cluster\"},';
    var lineArray = data.toString().split('\n');
    var destIPSet = new Set();
    var serviceSet = new Set();
    var attackSet = new Set();
    var attackString = '';
    for (var i = 0; i < lineArray.length - 1; ++i) {
        var valueArray = lineArray[i].split('\t');
        if (parseInt(valueArray[17]) === -1 && (parseInt(valueArray[14]) + parseInt(valueArray[15]) + parseInt(valueArray[16]) !== 0)) {
            // Generate destination IP nodes
            destIPSet.add(valueArray[20]);
            // Generate service nodes
            serviceSet.add(valueArray[1] + '-' + valueArray[20].split(':')[7]);
            // Generate attack nodes
            // id format: ATT-last 4 of destIP-start time-service
            // name format: ATT-last 4 of destIP-last 4 of sourceIP-service

            var detectedIDS =  valueArray[14] != '0' ? 'Yes' : 'No';
            var detectedMalware = valueArray[15] != '0' ? 'Yes' : 'No';
            var detectedShellCode = valueArray[16] != '0' ? 'Yes' : 'No';

            var attackTypeStr = '';
            if (detectedIDS === 'Yes') attackTypeStr += 'ids';
            if (detectedMalware === 'Yes') {
                if (attackTypeStr.length > 0) attackTypeStr += '-';
                attackTypeStr += 'mal';
            }
            if (detectedShellCode === 'Yes') {
                if (attackTypeStr.length > 0) attackTypeStr += '-';
                attackTypeStr += "shc";
            }

            attackSet.add('ATT' + '-' + valueArray[20].split(':')[7] + '-' + valueArray[22] + '-'  + valueArray[1] + '-&' + attackTypeStr);
            attackString += '{\"nodeType\": \"attack\", \"id\": \" ATT' + '-' + valueArray[20].split(':')[7] + '-' + valueArray[22] + '-'  + valueArray[1] + '\", \"name\": \"ATT' + '-' + valueArray[20].split(':')[7] + '-' + valueArray[18].split(':')[7] + '-' + valueArray[1] + '\", \"date\": \"' + dataDate + '\", \"host\": \"' + valueArray[20] +'\", \"sourceIP\": \"' + valueArray[18] + '\", \"ids_detection\": \"' + detectedIDS + '\", \"malware_detection\": \"' + detectedMalware + '\", \"shellCode_detection\": \"' + detectedShellCode + '\"},';
        }
    }
    // Output destination IP nodes
    for (var item of destIPSet) {
        dataString += '{\"nodeType\": \"destIP\", \"id\": \"' + item.split(':')[7] + '\", \"name\": \"' + item + '\"},';
    }
    // Output service nodes
    for (var item of serviceSet) {
        dataString += '{\"nodeType\": \"service\", \"id\": \"' + item + '\", \"name\": \"' + item.split('-')[0] + '\", \"host\": \"' + item.split('-')[1] + '\"},';
    }

    // Concatenate the attackString to the dataString
    dataString += attackString;
        // Remove last comma
        dataString = dataString.substring(0, dataString.length - 1);

    dataString += '], \"links\": [';

    // Links from MainCluster to destination IPs
    for (var item of destIPSet) {
        dataString += '{\"source\": \"MainCluster\", \"target\": \"' + item.split(':')[7] + '\"},';
    }

    // Links form destination IPs to their services
    for (var destItem of destIPSet) {
        for (var serviceItem of serviceSet) {
            // var service = serviceItem.split('-')[0];
            var last4OfIP = serviceItem.split('-')[1];
            if (last4OfIP === destItem.split(':')[7]) {
                dataString += '{\"source\": \"' + destItem.split(':')[7] + '\", \"target\": \"' + serviceItem + '\"},';
            }
        }
    }

    // Links from services to their attacks
    for (var serviceItem2 of serviceSet) {
        for (var attackItem of attackSet) {
            var attackLast4OfDestIP = attackItem.split('-')[1];
            var attackService = attackItem.split('-')[3];
            var serviceLast4OfHostIP = serviceItem2.split('-')[1];
            var serviceType = serviceItem2.split('-')[0];
            var attackID = attackItem.split('&')[0];
            attackID = attackID.substring(0, attackID.length - 1);
            if (attackLast4OfDestIP === serviceLast4OfHostIP && attackService === serviceType) {
                dataString += '{\"source\": \"' + serviceItem2 + '\", \"target\": \"' + attackID + '\", \"attackType\": \"' + attackItem.split('&')[1] + '\"},';
            }
        }
    }

    // Write out parsed file
    dataString = dataString.substring(0, dataString.length - 1);
    fs.writeFile(fileNameJSON, '{\"nodes\":[' + dataString + ']}', (err) => { if (err) throw err });
});