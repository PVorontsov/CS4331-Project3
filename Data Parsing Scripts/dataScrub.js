// Jason Vermillion
// 04/18/2019

var fs = require('fs');

var args = [];
process.argv.forEach(function (val, index, array) {
    if (index === 2) args.push(val);
});

var fileName = args[0];
var fileNameTxt = fileName + '.txt';
// var fileNameJSON = fileName + '.json';
var fileNameShortJSON = fileName + '-short.json';

fs.readFile(fileNameTxt, (err, data) => {
    if (err) throw err;
    // var dataString = '';
    var dataString2 = '';
    var lineArray = data.toString().split('\n');
    for (var i = 0; i < lineArray.length - 1; ++i) {
        var valueArray = lineArray[i].split('\t');
        // dataString += '{\"duration\":\"' + valueArray[0] + '\",\"service\":\"' + valueArray[1] + '\",\"source_bytes\":\"' + valueArray[2] + '\",\"dest_bytes\":\"' + valueArray[3] + '\",\"count\":\"' + valueArray[4] + '\",\"same_srv_rate\":\"' + valueArray[5] + '\","serror_rate\":\"' + valueArray[6] + '\",\"srv_serror_rate\":\"' + valueArray[7] + '\",\"dst_host_count\":\"' + valueArray[8] + '\",\"dst_host_srv_count\":\"' + valueArray[9] + '\",\"dst_host_same_src_port_rate\":\"' + valueArray[10] + '\",\"dst_host_serror_rate\":\"' + valueArray[11] + '\",\"dst_host_srv_serror_rate\":\"' + valueArray[12] + '\",\"flag\":\"' + valueArray[13] + '\",\"ids_detection\":\"' + valueArray[14] + '\",\"malware_detection\":\"' + valueArray[15] + '\",\"ashula_detection\":\"' + valueArray[16] + '\",\"label\":\"' + valueArray[17] + '\",\"source_ip\":\"' + valueArray[18] + '\",\"source_port\":\"' + valueArray[19] + '\",\"dest_ip\":\"' + valueArray[20] + '"\,\"dest_port\":\"' + valueArray[21] + '\",\"start_time\":\"' + valueArray[22] + '\",\"unknown_field\":\"' + valueArray[23] + '\"}';

        if (parseInt(valueArray[17]) === -1 && (parseInt(valueArray[14]) + parseInt(valueArray[15]) + parseInt(valueArray[16]) !== 0)) { 
            dataString2 += '{\"service\":\"' + valueArray[1] + '\",\"ids_detection\":\"' + valueArray[14] + '\",\"malware_detection\":\"' + valueArray[15] + '\",\"ashula_detection\":\"' + valueArray[16] + '\",\"label\":\"' + valueArray[17] + '\",\"source_ip\":\"' + valueArray[18] + '\",\"source_port\":\"' + valueArray[19] + '\",\"dest_ip\":\"' + valueArray[20] + '"\,\"dest_port\":\"' + valueArray[21]+ '\", \"start_time\": \"' + valueArray[22] + '\"},';
        }
    }
    dataString2 = dataString2.substring(0, dataString2.length - 1);
    // fs.writeFile(fileNameJSON, '[' + dataString + ']', (err) => { if (err) throw err });
    fs.writeFile(fileNameShortJSON, '[' + dataString2 + ']', (err) => { if (err) throw err });
});