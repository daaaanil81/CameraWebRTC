var connection = new WebSocket('ws://127.0.0.1:8080/ws'); // tcp server on c/c++
connection.onerror = function() {
    console.log("Connection...");
};

connection.onopen = function() {
    console.log("Send");
    connection.send("Hello"); // Send the message 'Ping' to the server
};

connection.onclose = function(event) {
    console.log("Close");
};

connection.onmessage = function(event) {};