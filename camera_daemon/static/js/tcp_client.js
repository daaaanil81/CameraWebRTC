const remoteVideo = document.getElementById('remoteVideo');
const configuration = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

var connection;
var localDescription;
var remoteDescription;
var localIce;
var remoteIces = [];
var remoteStream;
var sizeIce = 0;
var index = 0;
var flagSDP = true;
var candidate_result = null;
var options = {
    offerToReceiveAudio: false,
    offerToReceiveVideo: true
};
var flag_ICE = true;
var flag_Connection = false;

//var connection = new WebSocket('wss://109.86.197.114:45000/ws');
var connection = new WebSocket('wss://127.0.0.1:8080/ws');

connection.onerror = function() {
    console.log("Connection...");
};

connection.onopen = function() {
    console.log("Open");
};

connection.onclose = function(event) {
    console.log("Close");
    connectionRTC.close()
};

connection.onmessage = function(event) {
    console.log("Receive");
    var Type = event.data.substr(0, 3);
    if (Type === 'CON') {
        console.log(event.data);
        connectionRTC = new RTCPeerConnection(configuration);
        connectionRTC.onicecandidate = sendIceCandidate;
        connectionRTC.createOffer(setLocalDescription, onError, options);
        connectionRTC.addEventListener('track', gotRemoteStream);
        connectionRTC.addEventListener('iceconnectionstatechange', e => onIceStateChange(connectionRTC, e));
    }

    if (Type === 'SDP') {
        console.log("SDP");
        mes = event.data.substr(3);
        var description = { type: "answer", sdp: mes };
        connectionRTC.setRemoteDescription(new RTCSessionDescription(description)).catch(onError_Valid_Description);
        remoteDescription = description;
    }

    if (Type === 'ICE') {
        mes = event.data.substr(3);
        var candidate = new RTCIceCandidate({ sdpMLineIndex: 0, candidate: mes });
        remoteIces.push(candidate);
        console.log("Receive remote ice candidate");
        connectionRTC.addIceCandidate(candidate, sucIce, errorIce);
    }
};

function onIceStateChange(pc, event) {
    if (pc) {
        console.log(`ICE state: ${pc.iceConnectionState}`);
        console.log('ICE state change event: ', event);
    }
}

function sucIce() {
    console.log("Successful in candidate other user");
}

function errorIce() {
    console.log("Error in candidate client user");
    connection.send("ERROR");
    connection.send("Error in candidate client user.");
}

function onError_Valid_Description() {
    console.log("Error with Validate Description");
    flagSDP = false;
    connection.send("ERROR");
    connection.send("Error with server description.");
}

function setLocalDescription(description) {
    localDescription = description.sdp;
    connectionRTC.setLocalDescription(description);
    connection.send("SDP");
    connection.send(description.sdp);
}

function gotRemoteStream(e) {
    if (remoteVideo.srcObject !== e.streams[0]) {
        remoteVideo.srcObject = e.streams[0];
        console.log('pc2 received remote stream');
    }
}

function onError() {
    console.log("Error with description");
    connection.send('ERROR:' + "Error with client description.");
}

function sendIceCandidate(event) {
    console.log("Local Candidate");
    if (event.candidate) {
        console.log(event.candidate.candidate);
        var array = event.candidate.candidate.split(' ');
        var ip_address = array[4];
        if (event.candidate.candidate.indexOf(".local", 0) == -1 && ip_address.substr(0, 3) == '192') {
            localIce = event.candidate.candidate;
            connection.send("ICE");
            connection.send(event.candidate.candidate);
        }

    }
}
